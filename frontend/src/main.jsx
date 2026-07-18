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

function normalizeTechName(name = '') {
  return name
    .replace(/^Amazon Web Services$/i, 'AWS')
    .replace(/^Amazon CloudFront$/i, 'CloudFront')
    .replace(/^Amazon S3$/i, 'S3')
    .replace(/^Google Cloud$/i, 'GCP')
    .replace(/^Microsoft Azure$/i, 'Azure');
}

function compactTech(tech = []) {
  return [...new Set((tech || []).map(normalizeTechName).filter(Boolean))];
}

function techTone(name = '') {
  const n = name.toLowerCase();
  if (/graphql/.test(n)) return 'purple';
  if (/aws|cloudfront|s3|azure|gcp|cloudflare/.test(n)) return 'cloud';
  if (/admin|swagger|openapi/.test(n)) return 'warn';
  return 'muted';
}

function TechBadges({tech = [], max = 2}) {
  const items = compactTech(tech);
  const shown = items.slice(0, max);
  const rest = items.length - shown.length;
  return <div className="tech-inline">{shown.map(t => <Badge key={t} tone={techTone(t)}>{t}</Badge>)}{rest > 0 && <Badge tone="muted">+{rest}</Badge>}</div>;
}

function faviconFor(value = '') {
  const host = hostFromUrl(value);
  const letter = (host || '?').replace(/^www\./, '')[0]?.toUpperCase() || '?';
  return <span className="favicon">{letter}</span>;
}

function countBy(rows, getter) {
  const map = new Map();
  rows.forEach(r => {
    const key = getter(r);
    if (!key) return;
    map.set(key, (map.get(key) || 0) + 1);
  });
  return [...map.entries()].sort((a, b) => b[1] - a[1]);
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
  const http = result?.http || [];
  const subdomains = result?.subdomains?.length || 0;
  const live = http.filter(h => h.status_code && h.status_code < 500).length;
  const screenshots = result?.screenshots?.length || 0;
  const directories = result?.dirs?.length || 0;
  const interesting = [...(result?.subdomains || []), ...http, ...(result?.dirs || []), ...(result?.screenshots || [])].filter(r => r.interesting).length;
  const takeoverHints = http.filter(h => /github|heroku|netlify|s3|azure|cloudfront/i.test(`${h.title || ''} ${(h.tech || []).join(' ')}`)).length;
  const ips = new Set(http.map(h => h.ip).filter(Boolean)).size;
  const uniqueTech = new Set(http.flatMap(h => compactTech(h.tech))).size;
  const cdns = http.filter(h => /cloudflare|cloudfront|akamai|fastly/i.test((h.tech || []).join(' '))).length;
  return <>
    <div className="cards compact-cards">
      <div className="card"><span className="card-icon">🌐</span><b>{subdomains}</b><span>Subdomains</span></div>
      <div className="card"><span className="card-icon">🖥</span><b>{live}</b><span>Live Hosts</span></div>
      <div className="card"><span className="card-icon">📷</span><b>{screenshots}</b><span>Screenshots</span></div>
      <div className="card"><span className="card-icon">📂</span><b>{directories}</b><span>Directories</span></div>
      <div className="card hot"><span className="card-icon">🔥</span><b>{interesting}</b><span>Interesting</span></div>
      <div className="card warn"><span className="card-icon">⚠</span><b>{takeoverHints}</b><span>Takeover Hints</span></div>
    </div>
    <div className="infra-stats"><Badge>IPs {ips}</Badge><Badge>Unique Tech {uniqueTech}</Badge><Badge>CDNs {cdns}</Badge><Badge>Cloud Providers {http.filter(h => /aws|azure|gcp|cloudflare/i.test((h.tech || []).join(' '))).length}</Badge></div>
  </>;
}

function ProgressPanel({scan, result}) {
  const stage = scan?.stage || 'queued';
  const status = scan?.status || 'idle';
  const totalHosts = result?.subdomains?.length || 0;
  const liveHosts = result?.http?.length || 0;
  const dirCount = result?.dirs?.length || 0;
  const screenshotCount = result?.screenshots?.length || 0;
  const stages = [
    ['subdomains', 'Subdomains', `${totalHosts}/${totalHosts || '—'}`],
    ['httpx', 'Httpx', `${liveHosts}/${totalHosts || '—'}`],
    ['ffuf', 'FFUF', `${dirCount} paths`],
    ['screenshots', 'Gowitness', `${screenshotCount} shots`],
  ];
  const activeIndex = stages.findIndex(([key]) => stage.includes(key));
  const complete = status === 'complete';
  return <div className="progress-panel">
    <div className="panel-title"><span>Recon Progress</span><Badge tone={status === 'failed' ? 'server' : complete ? 'ok' : 'redirect'}>{status}</Badge></div>
    <div className="stage-list">{stages.map(([key, label], idx) => {
      const done = complete || idx < activeIndex;
      const active = idx === activeIndex && !complete;
      return <div key={key} className={`stage ${done ? 'done' : ''} ${active ? 'active' : ''}`}><span>{done ? '✓' : active ? '●' : '○'}</span><b>{label}</b><em>{stages[idx][2]}</em><small>{done ? `Completed in ${fmtDuration(scan)}` : active ? 'Running…' : 'Queued'}</small></div>;
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
  const chips = ['Alive', 'Interesting', 'APIs', 'Login', 'Admin', 'GraphQL', 'Swagger', 'Takeover'];
  const toggleChip = chip => setFilters({...filters, chips: filters.chips.includes(chip) ? filters.chips.filter(c => c !== chip) : [...filters.chips, chip]});
  return <>
    <div className="filters compact-filters">
      <input className="wide" placeholder="/ Search host, title, tech, IP, tag..." value={filters.q} onChange={e => setFilters({...filters, q: e.target.value})}/>
      <input placeholder="Status" value={filters.status} onChange={e => setFilters({...filters, status: e.target.value})}/>
      <input placeholder="Technology" value={filters.tech} onChange={e => setFilters({...filters, tech: e.target.value})}/>
      <input placeholder="IP / ASN" value={filters.ip} onChange={e => setFilters({...filters, ip: e.target.value})}/>
    </div>
    <div className="filter-chips">{chips.map(chip => <button key={chip} className={filters.chips.includes(chip) ? 'chip active' : 'chip'} onClick={() => toggleChip(chip)}>{filters.chips.includes(chip) ? '☑' : '☐'} {chip}</button>)}</div>
  </>;
}

function applyFilters(rows, filters) {
  return rows.filter(row => {
    const blob = JSON.stringify({...row, tags: tagsFor(row)}).toLowerCase();
    return (!filters.q || blob.includes(filters.q.toLowerCase())) &&
      (!filters.status || String(row.status_code || '').includes(filters.status)) &&
      (!filters.tech || blob.includes(filters.tech.toLowerCase())) &&
      (!filters.ip || String(row.ip || '').includes(filters.ip)) &&
      (!filters.chips.includes('Interesting') || row.interesting) &&
      (!filters.chips.includes('Alive') || (row.status_code && row.status_code < 500)) &&
      (!filters.chips.includes('APIs') || /api/i.test(blob)) &&
      (!filters.chips.includes('Login') || /login|signin|sso|auth/i.test(blob)) &&
      (!filters.chips.includes('Admin') || /admin|manage|console|dashboard/i.test(blob)) &&
      (!filters.chips.includes('GraphQL') || /graphql/i.test(blob)) &&
      (!filters.chips.includes('Swagger') || /swagger|openapi/i.test(blob)) &&
      (!filters.chips.includes('Takeover') || /github|heroku|netlify|s3|azure|cloudfront/i.test(blob));
  });
}

function AssetTable({rows, kind, selectRow, selectedIds, toggleSelected, markInteresting}) {
  const [filters, setFilters] = useState({q: '', status: '', tech: '', ip: '', chips: []});
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
        <td><div className="host-cell">{faviconFor(value)}<div><b>{hostFromUrl(value)}</b><div className="subtext">{value}</div></div></div></td>
        <td>{row.status_code ? <Badge tone={statusClass(row.status_code)}>{row.status_code}</Badge> : <span className="muted">—</span>}</td>
        <td>{row.title || row.path || <span className="muted">—</span>}</td>
        <td>{row.ip || <span className="muted">—</span>}</td>
        <td><TechBadges tech={row.tech} /></td>
        <td>{(row.sources || []).join(', ') || row.base_url || <span className="muted">—</span>}</td>
        <td>{tags.length ? tags.map(t => <Badge key={t} tone={t.includes('🔥') ? 'hot' : 'muted'}>{t}</Badge>) : <span className="muted">—</span>}</td>
        <td className="actions" onClick={e => e.stopPropagation()}><button onClick={() => window.open(value, '_blank')}>🌐</button><button onClick={() => copy(value)}>📋</button><button onClick={() => markInteresting(kind, row)}>⭐</button><button title="Screenshot">📸</button><button title="Run nuclei">⚡</button><button title="More">⋮</button></td>
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

function DetailsPanel({row, result, close, markInteresting}) {
  const http = result?.http || [];
  if (!row) {
    const codes = countBy(http, r => r.status_code).slice(0, 5);
    const techs = countBy(http.flatMap(h => compactTech(h.tech)).map(t => ({t})), r => r.t).slice(0, 6);
    return <aside className="details empty"><h3>Details</h3><p>Select a host to inspect technologies, headers, tags, and quick actions.</p><div className="mini-chart"><b>Response Codes</b>{codes.map(([code, n]) => <div className="bar-row" key={code}><span>{code}</span><i style={{width: `${Math.min(100, n * 8)}%`}} /> <em>{n}</em></div>)}</div><div className="mini-chart"><b>Top Technologies</b>{techs.map(([tech, n]) => <div className="bar-row" key={tech}><span>{tech}</span><i style={{width: `${Math.min(100, n * 8)}%`}} /> <em>{n}</em></div>)}</div><div className="timeline"><b>Scan Timeline</b><p>Subdomains → Httpx → FFUF → Gowitness → Finished</p></div></aside>;
  }
  const value = row.url || row.name || row.image_path;
  const cdn = compactTech(row.tech).find(t => /cloudfront|cloudflare|akamai|fastly/i.test(t)) || '—';
  const asn = /amazon|aws|cloudfront|s3/i.test((row.tech || []).join(' ')) ? 'Amazon' : /cloudflare/i.test((row.tech || []).join(' ')) ? 'Cloudflare' : '—';
  return <aside className="details"><button className="close" onClick={close}>×</button><div className="details-host">{faviconFor(value)}<h3>{hostFromUrl(value)}</h3></div><p className="subtext">{value}</p><div className="detail-row"><span>Status</span>{row.status_code ? <Badge tone={statusClass(row.status_code)}>{row.status_code}</Badge> : '—'}</div><div className="detail-row"><span>IP</span>{row.ip || '—'}</div><div className="detail-row"><span>ASN</span>{asn}</div><div className="detail-row"><span>CDN</span>{cdn}</div><div className="detail-row"><span>Title</span>{row.title || row.path || '—'}</div><div className="detail-row"><span>Technologies</span><TechBadges tech={row.tech} max={8}/></div><div className="detail-row"><span>Tags</span>{tagsFor(row).map(t => <Badge key={t}>{t}</Badge>)}</div><div className="detail-block"><span>Headers sent</span><pre>{JSON.stringify(row.headers_sent || {}, null, 2)}</pre></div><div className="detail-actions"><button onClick={() => window.open(value, '_blank')}>🌐 Open</button><button onClick={() => navigator.clipboard?.writeText(value)}>📋 Copy URL</button><button>📸 Screenshot</button><button>🔍 Whois</button><button>⚡ Run Nuclei</button><button>🕷 Crawl</button><button onClick={() => markInteresting(row.kind, row)}>⭐ Bookmark</button></div></aside>;
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
      <SidebarGroup title="Scan History">{(result?.scans || []).map(s => <button className="target scan-history-item" key={s.id} onClick={() => j(`${API}/targets/${active.id}/results?scan_id=${s.id}`).then(setResult)}><b>Scan #{s.id}</b><span>{ago(s.created_at)} · {s.status}</span></button>)}</SidebarGroup>
      <SidebarGroup title="Wordlists"><label>Subdomain upload<input type="file" onChange={e => upload('subdomain', e.target.files[0])}/></label><label>Dirb upload<input type="file" onChange={e => upload('dirb', e.target.files[0])}/></label><select onChange={e => setOpts({...opts, subdomain_wordlist_id: e.target.value})}><option value="">Subdomain wordlist</option>{wordlists.filter(w => w.kind === 'subdomain').map(w => <option key={w.id} value={w.id}>{w.name}</option>)}</select><select onChange={e => setOpts({...opts, dirb_wordlist_id: e.target.value})}><option value="">Dirb wordlist</option>{wordlists.filter(w => w.kind === 'dirb').map(w => <option key={w.id} value={w.id}>{w.name}</option>)}</select></SidebarGroup>
      <SidebarGroup title="Request Settings" defaultOpen={false}>{settings && <><input value={settings.user_agent || ''} onChange={e => setSettings({...settings, user_agent: e.target.value})} placeholder="User-Agent"/><input value={settings.proxy || ''} onChange={e => setSettings({...settings, proxy: e.target.value})} placeholder="Proxy"/><textarea placeholder="Header: value per line" value={settings.headerLines ?? Object.entries(settings.headers || {}).map(([k, v]) => `${k}: ${v}`).join('\n')} onChange={e => setSettings({...settings, headerLines: e.target.value})}/><button onClick={saveSettings}>Save settings</button></>}</SidebarGroup>
      <SidebarGroup title="FFUF Options" defaultOpen={false}><input placeholder="extensions php,txt" onChange={e => setOpts({...opts, extensions: e.target.value})}/><input placeholder="match codes" value={opts.ffuf_match_codes} onChange={e => setOpts({...opts, ffuf_match_codes: e.target.value})}/><label><input type="checkbox" checked={opts.ffuf_recursive} onChange={e => setOpts({...opts, ffuf_recursive: e.target.checked})}/> Recursive</label></SidebarGroup>
      <SidebarGroup title="Import / Export" defaultOpen={false}><button onClick={() => active && window.open(`${API}/targets/${active.id}/export?format=json`, '_blank')}>Export JSON</button><button onClick={() => active && window.open(`${API}/targets/${active.id}/export?format=csv`, '_blank')}>Export CSV</button></SidebarGroup>
    </aside>
    <section className="workspace"><SummaryCards result={result}/><ProgressPanel scan={scanStatus} result={result}/><div className="tabs">{TABS.map(t => <button className={tab === t ? 'sel' : ''} onClick={() => setTab(t)} key={t}>{t} <span>{t === 'Subdomains' ? subdomainRows.length : t === 'Live Hosts' ? httpRows.length : t === 'Directories' ? dirRows.length : t === 'Screenshots' ? (result?.screenshots || []).length : (result?.raw || []).length}</span></button>)}<div className="export-buttons"><button onClick={() => active && window.open(`${API}/targets/${active.id}/export?format=json`, '_blank')}>Export JSON</button><button onClick={() => active && window.open(`${API}/targets/${active.id}/export?format=csv`, '_blank')}>Export CSV</button></div></div>
      {tab === 'Subdomains' && <AssetTable rows={subdomainRows} kind="subdomains" selectRow={setDetail} selectedIds={selectedIds} toggleSelected={toggleSelected} markInteresting={markInteresting}/>} 
      {tab === 'Live Hosts' && <><h3>200 OK</h3><AssetTable rows={http200} kind="http" selectRow={setDetail} selectedIds={selectedIds} toggleSelected={toggleSelected} markInteresting={markInteresting}/><h3>Other Status Codes</h3><AssetTable rows={httpOther} kind="http" selectRow={setDetail} selectedIds={selectedIds} toggleSelected={toggleSelected} markInteresting={markInteresting}/></>} 
      {tab === 'Directories' && <AssetTable rows={dirRows} kind="dirs" selectRow={setDetail} selectedIds={selectedIds} toggleSelected={toggleSelected} markInteresting={markInteresting}/>} 
      {tab === 'Screenshots' && <ScreenshotGallery rows={result?.screenshots || []} selectRow={setDetail} markInteresting={markInteresting}/>} 
      {tab === 'Raw Logs' && <RawConsole rows={result?.raw || []}/>} 
    </section><DetailsPanel row={detail} result={result} close={() => setDetail(null)} markInteresting={markInteresting}/></main>
  </div>;
}

createRoot(document.getElementById('root')).render(<App/>);
