import React, {useEffect, useMemo, useState} from 'react';
import {createRoot} from 'react-dom/client';
import './style.css';

const API = '/api';
const TABS = ['Subdomains', 'Live Hosts', 'Directories', 'Screenshots', 'Raw Logs'];

async function j(url, options = {}) {
  const r = await fetch(url, {headers: {'Content-Type': 'application/json'}, ...options});
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

function usePoll(scanId, onTick) {
  useEffect(() => {
    if (!scanId) return;
    const id = setInterval(async () => onTick?.(), 2000);
    return () => clearInterval(id);
  }, [scanId, onTick]);
}

function fmtDuration(scan) {
  const start = scan?.started_at || scan?.created_at;
  if (!start) return '—';
  const end = scan?.finished_at || new Date().toISOString();
  const seconds = Math.max(0, Math.floor((new Date(end) - new Date(start)) / 1000));
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  return m ? `${m}m ${s}s` : `${s}s`;
}

function ago(iso) {
  if (!iso) return '—';
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  return `${Math.floor(minutes / 60)}h ago`;
}

function hostFromUrl(value = '') {
  try { return new URL(value).host; } catch { return value; }
}

function statusClass(status) {
  if (status >= 200 && status < 300) return 'ok';
  if (status >= 300 && status < 400) return 'redirect';
  if (status === 401 || status === 403) return 'auth';
  if (status >= 400 && status < 500) return 'client';
  if (status >= 500) return 'server';
  return 'muted';
}

function tagsFor(row) {
  const haystack = `${row.url || row.name || ''} ${row.title || ''} ${(row.tech || []).join(' ')}`.toLowerCase();
  const tags = [];
  if (row.is_new) tags.push('NEW');
  if (row.interesting) tags.push('🔥 Interesting');
  if (row.open_directory) tags.push('Index of');
  if (/admin|manage|console|dashboard/.test(haystack)) tags.push('Admin');
  if (/login|signin|sso|auth/.test(haystack)) tags.push('Login');
  if (/api|graphql|swagger|openapi/.test(haystack)) tags.push('API');
  if (/jenkins|kibana|grafana/.test(haystack)) tags.push('Dashboard');
  return tags;
}

function Badge({children, tone = 'muted'}) {
  return <span className={`badge ${tone}`}>{children}</span>;
}

function SidebarGroup({title, children, defaultOpen = true}) {
  const [open, setOpen] = useState(defaultOpen);
  return <div className="sidebar-group"><button className="group-title" onClick={() => setOpen(!open)}>{open ? '▾' : '▸'} {title}</button>{open && <div className="group-body">{children}</div>}</div>;
}

function SummaryCards({result}) {
  const subdomains = result?.subdomains?.length || 0;
  const live = (result?.http || []).filter(h => h.status_code && h.status_code < 500).length;
  const screenshots = result?.screenshots?.length || 0;
  const directories = result?.dirs?.length || 0;
  const interesting = [...(result?.subdomains || []), ...(result?.http || []), ...(result?.dirs || []), ...(result?.screenshots || [])].filter(r => r.interesting).length;
  const takeoverHints = (result?.http || []).filter(h => /github|heroku|netlify|s3|azure|cloudfront/i.test(`${h.title || ''} ${(h.tech || []).join(' ')}`)).length;
  return <div className="cards">
    <div className="card"><b>{subdomains}</b><span>Subdomains</span></div>
    <div className="card"><b>{live}</b><span>Live Hosts</span></div>
    <div className="card"><b>{screenshots}</b><span>Screenshots</span></div>
    <div className="card"><b>{directories}</b><span>Directories</span></div>
    <div className="card hot"><b>{interesting}</b><span>Interesting</span></div>
    <div className="card warn"><b>{takeoverHints}</b><span>Takeover Hints</span></div>
  </div>;
}

function ProgressPanel({scan}) {
  const stage = scan?.stage || 'queued';
  const status = scan?.status || 'idle';
  const stages = [
    ['subdomains', 'Subdomain enum'],
    ['httpx', 'Httpx live probe'],
    ['ffuf', 'FFUF content scan'],
    ['screenshots', 'Gowitness screenshots'],
  ];
  const activeIndex = stages.findIndex(([key]) => stage.includes(key));
  const complete = status === 'complete';
  return <div className="progress-panel">
    <div className="panel-title"><span>Recon Progress</span><Badge tone={status === 'failed' ? 'server' : complete ? 'ok' : 'redirect'}>{status}</Badge></div>
    <div className="stage-list">{stages.map(([key, label], idx) => {
      const done = complete || idx < activeIndex;
      const active = idx === activeIndex && !complete;
      return <div key={key} className={`stage ${done ? 'done' : ''} ${active ? 'active' : ''}`}><span>{done ? '✓' : active ? '●' : '○'}</span>{label}</div>;
    })}</div>
    <div className="elapsed">Elapsed: {fmtDuration(scan)} · Started: {ago(scan?.started_at || scan?.created_at)}</div>
    <div className="bar"><span style={{width: `${scan?.progress || 0}%`}} /></div>
  </div>;
}

function Header({domain, setDomain, run, result, targets, loadTarget}) {
  const scan = result?.active_scan;
  const target = result?.target?.domain || 'No target selected';
  const counts = `${result?.subdomains?.length || 0} subdomains | ${(result?.http || []).length} live results | ${result?.dirs?.length || 0} directories`;
  return <header>
    <div className="brand"><h1>{target}</h1><div className="header-meta"><Badge tone={scan?.status === 'complete' ? 'ok' : 'redirect'}>{scan?.status || 'ready'}</Badge><span>{counts}</span><span>Started: {ago(scan?.started_at || scan?.created_at)}</span></div></div>
    <div className="runbox"><select onChange={e => { const t = targets.find(x => String(x.id) === e.target.value); if (t) loadTarget(t); }}><option>Recent targets</option>{targets.slice(0, 12).map(t => <option key={t.id} value={t.id}>{t.domain}</option>)}</select><input className="target-input" value={domain} onChange={e => setDomain(e.target.value)} placeholder="example.com"/><button className="primary" onClick={run}>Run Recon</button></div>
  </header>;
}

function Filters({filters, setFilters}) {
  return <div className="filters">
    <input className="wide" placeholder="Search host, title, tech, IP, tag..." value={filters.q} onChange={e => setFilters({...filters, q: e.target.value})}/>
    <input placeholder="HTTP status" value={filters.status} onChange={e => setFilters({...filters, status: e.target.value})}/>
    <input placeholder="Technology" value={filters.tech} onChange={e => setFilters({...filters, tech: e.target.value})}/>
    <input placeholder="IP / ASN" value={filters.ip} onChange={e => setFilters({...filters, ip: e.target.value})}/>
    <label className="inline"><input type="checkbox" checked={filters.interesting} onChange={e => setFilters({...filters, interesting: e.target.checked})}/> Interesting only</label>
    <label className="inline"><input type="checkbox" checked={filters.alive} onChange={e => setFilters({...filters, alive: e.target.checked})}/> Alive only</label>
  </div>;
}

function applyFilters(rows, filters) {
  return rows.filter(row => {
    const blob = JSON.stringify({...row, tags: tagsFor(row)}).toLowerCase();
    return (!filters.q || blob.includes(filters.q.toLowerCase())) &&
      (!filters.status || String(row.status_code || '').includes(filters.status)) &&
      (!filters.tech || blob.includes(filters.tech.toLowerCase())) &&
      (!filters.ip || String(row.ip || '').includes(filters.ip)) &&
      (!filters.interesting || row.interesting) &&
      (!filters.alive || (row.status_code && row.status_code < 500));
  });
}

function AssetTable({rows, kind, selectRow, selectedIds, toggleSelected, markInteresting}) {
  const [filters, setFilters] = useState({q: '', status: '', tech: '', ip: '', interesting: false, alive: false});
  const filtered = useMemo(() => applyFilters(rows, filters), [rows, filters]);
  const copy = value => navigator.clipboard?.writeText(value).catch(() => {});
  return <>
    <Filters filters={filters} setFilters={setFilters}/>
    <div className="bulkbar"><label><input type="checkbox" onChange={e => filtered.forEach(r => toggleSelected(r.id, e.target.checked))}/> Select visible</label><span>{selectedIds.size} selected</span><button onClick={() => copy(filtered.filter(r => selectedIds.has(r.id)).map(r => r.url || r.name).join('\n'))}>Copy selected</button></div>
    <table><thead><tr><th></th><th>Host</th><th>Status</th><th>Title</th><th>IP</th><th>Tech</th><th>Source</th><th>Tags</th><th>Actions</th></tr></thead><tbody>{filtered.map(row => {
      const value = row.url || row.name;
      const tags = tagsFor(row);
      return <tr key={`${kind}-${row.id}`} onClick={() => selectRow({...row, kind})} className={row.is_new ? 'new' : ''}>
        <td onClick={e => e.stopPropagation()}><input type="checkbox" checked={selectedIds.has(row.id)} onChange={e => toggleSelected(row.id, e.target.checked)}/></td>
        <td><b>{hostFromUrl(value)}</b><div className="subtext">{value}</div></td>
        <td>{row.status_code ? <Badge tone={statusClass(row.status_code)}>{row.status_code}</Badge> : <span className="muted">—</span>}</td>
        <td>{row.title || row.path || <span className="muted">—</span>}</td>
        <td>{row.ip || <span className="muted">—</span>}</td>
        <td>{(row.tech || []).slice(0, 4).map(t => <Badge key={t}>{t}</Badge>)}</td>
        <td>{(row.sources || []).join(', ') || row.base_url || <span className="muted">—</span>}</td>
        <td>{tags.length ? tags.map(t => <Badge key={t} tone={t.includes('🔥') ? 'hot' : 'muted'}>{t}</Badge>) : <span className="muted">—</span>}</td>
        <td className="actions" onClick={e => e.stopPropagation()}><button onClick={() => window.open(value, '_blank')}>🌐</button><button onClick={() => copy(value)}>📋</button><button onClick={() => markInteresting(kind, row)}>⭐</button></td>
      </tr>;
    })}</tbody></table>
  </>;
}

function ScreenshotGallery({rows, selectRow, markInteresting}) {
  return <div className="gallery">{rows.map(s => <figure key={s.id} onClick={() => selectRow({...s, kind: 'screenshots'})}><a href={s.image_url} target="_blank" rel="noreferrer"><img src={s.image_url}/></a><figcaption><b>{hostFromUrl(s.url)}</b><div><Badge tone="ok">Screenshot</Badge>{s.interesting && <Badge tone="hot">🔥</Badge>}</div><button onClick={e => { e.preventDefault(); e.stopPropagation(); markInteresting('screenshots', s); }}>⭐ Bookmark</button></figcaption></figure>)}</div>;
}

function RawConsole({rows}) {
  return <div className="console"><div className="console-title">Live / Raw Output</div>{rows.length ? rows.map(r => <div key={r.id} className="logline"><span>[{r.tool}]</span> {r.stage} · {r.path}</div>) : <div className="logline muted">No raw output yet. Logs will appear after stages complete.</div>}</div>;
}

function DetailsPanel({row, close, markInteresting}) {
  if (!row) return <aside className="details empty"><h3>Details</h3><p>Select a host, directory, subdomain, or screenshot.</p></aside>;
  const value = row.url || row.name || row.image_path;
  return <aside className="details"><button className="close" onClick={close}>×</button><h3>{hostFromUrl(value)}</h3><div className="detail-row"><span>Status</span>{row.status_code ? <Badge tone={statusClass(row.status_code)}>{row.status_code}</Badge> : '—'}</div><div className="detail-row"><span>IP</span>{row.ip || '—'}</div><div className="detail-row"><span>Title</span>{row.title || row.path || '—'}</div><div className="detail-row"><span>Tech</span>{(row.tech || []).join(', ') || '—'}</div><div className="detail-row"><span>Tags</span>{tagsFor(row).map(t => <Badge key={t}>{t}</Badge>)}</div><div className="detail-block"><span>Headers sent</span><pre>{JSON.stringify(row.headers_sent || {}, null, 2)}</pre></div><div className="detail-actions"><button onClick={() => window.open(value, '_blank')}>Open</button><button onClick={() => navigator.clipboard?.writeText(value)}>Copy</button><button onClick={() => markInteresting(row.kind, row)}>Bookmark</button></div></aside>;
}

function App() {
  const [domain, setDomain] = useState('');
  const [targets, setTargets] = useState([]);
  const [active, setActive] = useState(null);
  const [result, setResult] = useState(null);
  const [scan, setScan] = useState(null);
  const [tab, setTab] = useState('Subdomains');
  const [settings, setSettings] = useState(null);
  const [wordlists, setWordlists] = useState([]);
  const [selectedIds, setSelectedIds] = useState(new Set());
  const [detail, setDetail] = useState(null);
  const [opts, setOpts] = useState({recursion_depth: 2, ffuf_threads: 25, ffuf_match_codes: '200,204,301,302,307,401,403', ffuf_recursive: false, run_ffuf: true, run_screenshots: true});

  const refresh = async () => {
    const [targetRows, wordlistRows, appSettings] = await Promise.all([j(`${API}/targets`), j(`${API}/wordlists`), j(`${API}/settings`)]);
    setTargets(targetRows); setWordlists(wordlistRows); setSettings(appSettings);
    if (active) setResult(await j(`${API}/targets/${active.id}/results`));
  };
  useEffect(() => { refresh(); }, []);
  usePoll(scan?.id, refresh);

  async function run() {
    const payload = {domain, ...opts, subdomain_wordlist_id: opts.subdomain_wordlist_id ? Number(opts.subdomain_wordlist_id) : null, dirb_wordlist_id: opts.dirb_wordlist_id ? Number(opts.dirb_wordlist_id) : null};
    const res = await j(`${API}/scans/run`, {method: 'POST', body: JSON.stringify(payload)});
    setScan({id: res.scan_id}); setActive({id: res.target_id, domain}); await refresh();
  }
  async function loadTarget(t) { setActive(t); setResult(await j(`${API}/targets/${t.id}/results`)); }
  async function deleteTarget(t) {
    const ok = window.confirm(`Delete target ${t.domain} and all scans/results/raw-output references for it? This cannot be undone.`);
    if (!ok) return;
    await j(`${API}/targets/${t.id}`, {method: 'DELETE'});
    if (active?.id === t.id) { setActive(null); setResult(null); setDetail(null); }
    await refresh();
  }
  async function upload(kind, file) { if (!file) return; const fd = new FormData(); fd.append('file', file); await fetch(`${API}/wordlists/${kind}`, {method: 'POST', body: fd}); await refresh(); }
  async function saveSettings() { const body = {...settings, headers: Object.fromEntries((settings.headerLines || '').split('\n').filter(Boolean).map(l => { const [k, ...v] = l.split(':'); return [k.trim(), v.join(':').trim()]; }))}; delete body.headerLines; setSettings(await j(`${API}/settings`, {method: 'PUT', body: JSON.stringify(body)})); }
  async function markInteresting(kind, row) { await j(`${API}/${kind}/${row.id}/interesting`, {method: 'PATCH', body: JSON.stringify({interesting: !row.interesting, note: row.note || '', tag: row.tag || ''})}); await refresh(); }
  const toggleSelected = (id, checked) => setSelectedIds(prev => { const next = new Set(prev); checked ? next.add(id) : next.delete(id); return next; });

  const httpRows = result?.http || [];
  const http200 = httpRows.filter(h => h.status_code === 200);
  const httpOther = httpRows.filter(h => h.status_code !== 200);
  const subdomainRows = (result?.subdomains || []).map(s => ({...s, url: s.name}));
  const dirRows = result?.dirs || [];
  const scanStatus = result?.active_scan || scan;

  return <div>
    <Header domain={domain} setDomain={setDomain} run={run} result={result} targets={targets} loadTarget={loadTarget}/>
    <main className="layout"><aside className="sidebar">
      <SidebarGroup title="⭐ Favorite Targets"><p className="muted">Bookmark rows with ⭐. Favorite target pinning is next.</p></SidebarGroup>
      <SidebarGroup title="Recent Targets">{targets.map(t => <div className="target-row" key={t.id}><button className="target" onClick={() => loadTarget(t)}>{t.domain}<span>{t.scan_count} scans</span></button><button className="danger small" title={`Delete ${t.domain}`} onClick={() => deleteTarget(t)}>Delete</button></div>)}</SidebarGroup>
      <SidebarGroup title="Scan History">{(result?.scans || []).map(s => <button className="target" key={s.id} onClick={() => j(`${API}/targets/${active.id}/results?scan_id=${s.id}`).then(setResult)}>Scan {s.id}<span>{s.status}</span></button>)}</SidebarGroup>
      <SidebarGroup title="Wordlists"><label>Subdomain upload<input type="file" onChange={e => upload('subdomain', e.target.files[0])}/></label><label>Dirb upload<input type="file" onChange={e => upload('dirb', e.target.files[0])}/></label><select onChange={e => setOpts({...opts, subdomain_wordlist_id: e.target.value})}><option value="">Subdomain wordlist</option>{wordlists.filter(w => w.kind === 'subdomain').map(w => <option key={w.id} value={w.id}>{w.name}</option>)}</select><select onChange={e => setOpts({...opts, dirb_wordlist_id: e.target.value})}><option value="">Dirb wordlist</option>{wordlists.filter(w => w.kind === 'dirb').map(w => <option key={w.id} value={w.id}>{w.name}</option>)}</select></SidebarGroup>
      <SidebarGroup title="Request Settings" defaultOpen={false}>{settings && <><input value={settings.user_agent || ''} onChange={e => setSettings({...settings, user_agent: e.target.value})} placeholder="User-Agent"/><input value={settings.proxy || ''} onChange={e => setSettings({...settings, proxy: e.target.value})} placeholder="Proxy"/><textarea placeholder="Header: value per line" value={settings.headerLines ?? Object.entries(settings.headers || {}).map(([k, v]) => `${k}: ${v}`).join('\n')} onChange={e => setSettings({...settings, headerLines: e.target.value})}/><button onClick={saveSettings}>Save settings</button></>}</SidebarGroup>
      <SidebarGroup title="FFUF Options" defaultOpen={false}><input placeholder="extensions php,txt" onChange={e => setOpts({...opts, extensions: e.target.value})}/><input placeholder="match codes" value={opts.ffuf_match_codes} onChange={e => setOpts({...opts, ffuf_match_codes: e.target.value})}/><label><input type="checkbox" checked={opts.ffuf_recursive} onChange={e => setOpts({...opts, ffuf_recursive: e.target.checked})}/> Recursive</label></SidebarGroup>
      <SidebarGroup title="Import / Export" defaultOpen={false}><button onClick={() => active && window.open(`${API}/targets/${active.id}/export?format=json`, '_blank')}>Export JSON</button><button onClick={() => active && window.open(`${API}/targets/${active.id}/export?format=csv`, '_blank')}>Export CSV</button></SidebarGroup>
    </aside>
    <section className="workspace"><SummaryCards result={result}/><ProgressPanel scan={scanStatus}/><div className="tabs">{TABS.map(t => <button className={tab === t ? 'sel' : ''} onClick={() => setTab(t)} key={t}>{t} <span>{t === 'Subdomains' ? subdomainRows.length : t === 'Live Hosts' ? httpRows.length : t === 'Directories' ? dirRows.length : t === 'Screenshots' ? (result?.screenshots || []).length : (result?.raw || []).length}</span></button>)}<div className="export-buttons"><button onClick={() => active && window.open(`${API}/targets/${active.id}/export?format=json`, '_blank')}>Export JSON</button><button onClick={() => active && window.open(`${API}/targets/${active.id}/export?format=csv`, '_blank')}>Export CSV</button></div></div>
      {tab === 'Subdomains' && <AssetTable rows={subdomainRows} kind="subdomains" selectRow={setDetail} selectedIds={selectedIds} toggleSelected={toggleSelected} markInteresting={markInteresting}/>} 
      {tab === 'Live Hosts' && <><h3>200 OK</h3><AssetTable rows={http200} kind="http" selectRow={setDetail} selectedIds={selectedIds} toggleSelected={toggleSelected} markInteresting={markInteresting}/><h3>Other Status Codes</h3><AssetTable rows={httpOther} kind="http" selectRow={setDetail} selectedIds={selectedIds} toggleSelected={toggleSelected} markInteresting={markInteresting}/></>} 
      {tab === 'Directories' && <AssetTable rows={dirRows} kind="dirs" selectRow={setDetail} selectedIds={selectedIds} toggleSelected={toggleSelected} markInteresting={markInteresting}/>} 
      {tab === 'Screenshots' && <ScreenshotGallery rows={result?.screenshots || []} selectRow={setDetail} markInteresting={markInteresting}/>} 
      {tab === 'Raw Logs' && <RawConsole rows={result?.raw || []}/>} 
    </section><DetailsPanel row={detail} close={() => setDetail(null)} markInteresting={markInteresting}/></main>
  </div>;
}

createRoot(document.getElementById('root')).render(<App/>);
