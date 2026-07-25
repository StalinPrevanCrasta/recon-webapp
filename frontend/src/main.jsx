import React, {useEffect, useMemo, useState} from 'react';
import {createRoot} from 'react-dom/client';
import './style.css';

const API = '/api';
const TABS = ['Subdomains', 'Live Hosts', 'Content Paths', 'Screenshots', 'Raw Logs'];

async function j(url, options = {}) {
  const isForm = options.body instanceof FormData;
  const headers = isForm ? (options.headers || {}) : {'Content-Type': 'application/json', ...(options.headers || {})};
  const r = await fetch(url, {...options, headers});
  const contentType = r.headers.get('content-type') || '';
  const body = contentType.includes('application/json') ? await r.json() : await r.text();
  if (!r.ok) throw new Error(body?.detail || body || `Request failed: ${r.status}`);
  return body;
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
  if (row.is_new) tags.push('New');
  if (row.interesting) tags.push('Marked');
  if (row.open_directory) tags.push('Index of');
  if (row.confidence === 'confirmed') tags.push('Confirmed');
  if (row.confidence === 'possible') tags.push('Possible');
  if (row.confidence === 'filtered') tags.push('Filtered');
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
  return <div className="sidebar-group"><button className="group-title" onClick={() => setOpen(!open)}>{title}<span>{open ? 'Hide' : 'Show'}</span></button>{open && <div className="group-body">{children}</div>}</div>;
}

function SummaryCards({result}) {
  const http = result?.http || [];
  const subdomains = result?.subdomains?.length || 0;
  const live = http.filter(h => h.status_code && h.status_code < 500).length;
  const screenshots = result?.screenshots?.length || 0;
  const dirs = result?.dirs || [];
  const confirmedDirs = dirs.filter(d => d.confidence === 'confirmed').length;
  const possibleDirs = dirs.filter(d => d.confidence === 'possible').length;
  const filteredDirs = dirs.filter(d => d.confidence === 'filtered').length;
  const interesting = [...(result?.subdomains || []), ...http, ...(result?.dirs || []), ...(result?.screenshots || [])].filter(r => r.interesting).length;
  const takeoverHints = http.filter(h => /github|heroku|netlify|s3|azure|cloudfront/i.test(`${h.title || ''} ${(h.tech || []).join(' ')}`)).length;
  const ips = new Set(http.map(h => h.ip).filter(Boolean)).size;
  const uniqueTech = new Set(http.flatMap(h => compactTech(h.tech))).size;
  const cdns = http.filter(h => /cloudflare|cloudfront|akamai|fastly/i.test((h.tech || []).join(' '))).length;
  return <>
    <div className="cards compact-cards">
      <div className="card"><span className="card-label">DNS</span><b>{subdomains}</b><span>Subdomains</span></div>
      <div className="card"><span className="card-label">HTTP</span><b>{live}</b><span>Live hosts</span></div>
      <div className="card"><span className="card-label">VISUAL</span><b>{screenshots}</b><span>Screenshots</span></div>
      <div className="card"><span className="card-label">PATHS</span><b>{confirmedDirs}</b><span>Content paths</span><small>{possibleDirs} possible · {filteredDirs} filtered</small></div>
      <div className="card hot"><span className="card-label">MARKED</span><b>{interesting}</b><span>Marked</span></div>
      <div className="card warn"><span className="card-label">RISK</span><b>{takeoverHints}</b><span>Takeover hints</span></div>
    </div>
    <div className="infra-stats"><Badge>IPs {ips}</Badge><Badge>Unique Tech {uniqueTech}</Badge><Badge>CDNs {cdns}</Badge><Badge>Cloud Providers {http.filter(h => /aws|azure|gcp|cloudflare/i.test((h.tech || []).join(' '))).length}</Badge></div>
  </>;
}

function ProgressPanel({scan, result}) {
  const stage = scan?.stage || 'queued';
  const status = scan?.status || 'idle';
  const stageInfo = result?.stage_statuses || {};
  const totalHosts = result?.subdomains?.length || 0;
  const liveHosts = result?.http?.length || 0;
  const dirs = result?.dirs || [];
  const confirmed = dirs.filter(d => d.confidence === 'confirmed').length;
  const possible = dirs.filter(d => d.confidence === 'possible').length;
  const filtered = dirs.filter(d => d.confidence === 'filtered').length;
  const screenshotCount = result?.screenshots?.length || 0;
  const stages = [
    ['subdomains', 'Subdomains', `${totalHosts}/${totalHosts || '—'}`],
    ['httpx', 'Httpx', `${liveHosts}/${totalHosts || '—'}`],
    ['ffuf', 'FFUF', `${stageInfo.ffuf?.successful_hosts || 0}/${stageInfo.ffuf?.total || liveHosts || '—'} hosts · ${confirmed} confirmed · ${possible} possible · ${filtered} filtered · ${stageInfo.ffuf?.failed_hosts || 0} failed`],
    ['screenshots', 'Gowitness', `${screenshotCount} shots`],
  ];
  return <div className="progress-panel">
    <div className="panel-title"><span>Scan pipeline</span><Badge tone={status === 'failed' ? 'server' : status === 'partial' ? 'warn' : status === 'complete' ? 'ok' : 'redirect'}>{status}</Badge></div>
    <div className="stage-list">{stages.map(([key, label, text]) => {
      const info = stageInfo[key] || {};
      const state = info.status || (stage.includes(key) && status === 'running' ? 'running' : 'not_started');
      const done = state === 'complete';
      const active = state === 'running';
      const partial = state === 'partial';
      const failed = state === 'failed';
      const marker = done ? 'Done' : partial ? 'Part' : failed ? 'Fail' : active ? 'Run' : 'Wait';
      const labelText = done ? 'Complete' : partial ? 'Partial' : failed ? 'Failed' : active ? 'Running…' : 'Not started';
      return <div key={key} className={`stage ${done ? 'done' : ''} ${active ? 'active' : ''} ${partial ? 'partial' : ''} ${failed ? 'failed' : ''}`}><span>{marker}</span><b>{label}</b><em>{text}</em><small>{labelText}</small></div>;
    })}</div>
    {scan?.error && <div className="inline-alert">{scan.error}</div>}
    <div className="elapsed">Elapsed: {fmtDuration(scan)} · Started: {ago(scan?.started_at || scan?.created_at)}</div>
    <div className="bar"><span style={{width: `${scan?.progress || 0}%`}} /></div>
  </div>;
}

function Header({domain, setDomain, run, result, targets, loadTarget, runDisabled, runError}) {
  const scan = result?.active_scan;
  const target = result?.target?.domain || 'No target selected';
  const counts = `${result?.subdomains?.length || 0} subdomains | ${(result?.http || []).length} live results | ${result?.dirs?.length || 0} content paths`;
  return <header>
    <div className="brand"><h1>{target}</h1><div className="header-meta"><Badge tone={scan?.status === 'complete' ? 'ok' : 'redirect'}>{scan?.status || 'ready'}</Badge><span>{counts}</span><span>Started: {ago(scan?.started_at || scan?.created_at)}</span></div></div>
    <div className="runbox"><select onChange={e => { const t = targets.find(x => String(x.id) === e.target.value); if (t) loadTarget(t); }}><option>Recent targets</option>{targets.slice(0, 12).map(t => <option key={t.id} value={t.id}>{t.domain}</option>)}</select><input className="target-input" value={domain} onChange={e => setDomain(e.target.value)} placeholder="example.com"/><button className="secondary" title="Open live container logs" onClick={() => window.open('/logs', '_blank', 'noopener,noreferrer')}>View Logs</button><button className="primary" disabled={runDisabled} title={runError || ''} onClick={run}>{runDisabled ? 'Fix options' : 'Run scan'}</button></div>{runError && <div className="inline-alert">{runError}</div>}
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
    <div className="filter-chips">{chips.map(chip => <button key={chip} className={filters.chips.includes(chip) ? 'chip active' : 'chip'} onClick={() => toggleChip(chip)}>{chip}</button>)}</div>
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
    <table><thead><tr><th></th><th>Host</th><th>Status</th><th>Title</th><th>IP</th><th>Tech</th><th>Source</th><th>Tags</th><th>Confidence</th><th>Actions</th></tr></thead><tbody>{filtered.map(row => {
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
        <td>{tags.length ? tags.map(t => <Badge key={t} tone={t === 'Marked' ? 'hot' : t === 'Filtered' ? 'client' : t === 'Possible' ? 'warn' : t === 'Confirmed' ? 'ok' : 'muted'}>{t}</Badge>) : <span className="muted">—</span>}</td>
        <td>{row.confidence ? <Badge tone={row.confidence === 'confirmed' ? 'ok' : row.confidence === 'possible' ? 'warn' : row.confidence === 'filtered' ? 'client' : 'muted'}>{row.confidence}</Badge> : <span className="muted">—</span>}<div className="subtext">{row.size ? `${row.size} B` : ''}{row.words ? ` · ${row.words}w` : ''}</div></td>
        <td className="actions" onClick={e => e.stopPropagation()}><button onClick={() => window.open(value, '_blank')}>Open</button><button onClick={() => copy(value)}>Copy</button><button onClick={() => markInteresting(kind, row)}>Mark</button><button title="Screenshot">Shot</button><button title="Run nuclei">Nuclei</button></td>
      </tr>;
    })}</tbody></table>
  </>;
}

function ScreenshotGallery({rows, selectRow, markInteresting}) {
  return <div className="gallery">{rows.map(s => <figure key={s.id} onClick={() => selectRow({...s, kind: 'screenshots'})}><a href={s.image_url} target="_blank" rel="noreferrer"><img src={s.image_url}/></a><figcaption><b>{hostFromUrl(s.url)}</b><div><Badge tone="ok">Screenshot</Badge>{s.interesting && <Badge tone="hot">Marked</Badge>}</div><button onClick={e => { e.preventDefault(); e.stopPropagation(); markInteresting('screenshots', s); }}>Mark screenshot</button></figcaption></figure>)}</div>;
}

function RawConsole({rows}) {
  const [open, setOpen] = useState(null);
  async function toggle(row) {
    if (open?.id === row.id) { setOpen(null); return; }
    try { setOpen(await j(`${API}/raw/${row.id}`)); } catch (err) { setOpen({id: row.id, content: err.message || String(err)}); }
  }
  return <div className="console"><div className="console-title">Live / Raw Output</div>{rows.length ? rows.map(r => <div key={r.id} className="logwrap"><div className="logline"><span>[{r.tool}]</span> {r.stage} · {r.path}<button onClick={() => toggle(r)}>Open log</button></div>{open?.id === r.id && <pre className="logcontent">{open.content}{open.truncated ? '\n...[truncated]' : ''}</pre>}</div>) : <div className="logline muted">No raw output yet. Logs will appear after stages complete.</div>}</div>;
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
  return <aside className="details"><button className="close" onClick={close}>Close</button><div className="details-host">{faviconFor(value)}<h3>{hostFromUrl(value)}</h3></div><p className="subtext">{value}</p><div className="detail-row"><span>Status</span>{row.status_code ? <Badge tone={statusClass(row.status_code)}>{row.status_code}</Badge> : '—'}</div><div className="detail-row"><span>IP</span>{row.ip || '—'}</div><div className="detail-row"><span>ASN</span>{asn}</div><div className="detail-row"><span>CDN</span>{cdn}</div><div className="detail-row"><span>Title / Path</span>{row.title || row.path || '—'}</div><div className="detail-row"><span>Confidence</span>{row.confidence ? <Badge tone={row.confidence === 'confirmed' ? 'ok' : row.confidence === 'possible' ? 'warn' : row.confidence === 'filtered' ? 'client' : 'muted'}>{row.confidence}</Badge> : '—'}</div><div className="detail-row"><span>Size / Words / Lines</span>{[row.size && `${row.size} B`, row.words && `${row.words} words`, row.lines && `${row.lines} lines`].filter(Boolean).join(' · ') || '—'}</div><div className="detail-row"><span>Filtered Reason</span>{row.filtered_reason || '—'}</div><div className="detail-row"><span>Technologies</span><TechBadges tech={row.tech} max={8}/></div><div className="detail-row"><span>Tags</span>{tagsFor(row).map(t => <Badge key={t}>{t}</Badge>)}</div><div className="detail-block"><span>Headers sent</span><pre>{JSON.stringify(row.headers_sent || {}, null, 2)}</pre></div><div className="detail-actions"><button onClick={() => window.open(value, '_blank')}>Open</button><button onClick={() => navigator.clipboard?.writeText(value)}>Copy URL</button><button>Screenshot</button><button>Whois</button><button>Run Nuclei</button><button>Crawl</button><button onClick={() => markInteresting(row.kind, row)}>Mark</button></div></aside>;
}


function useContainerLogs({container, tail, paused, bufferLimit = 10000}) {
  const [lines, setLines] = useState([]);
  const [pending, setPending] = useState(0);
  const [status, setStatus] = useState('Disconnected');
  const [error, setError] = useState('');
  const pausedRef = React.useRef(paused);
  const reconnectRef = React.useRef(0);
  useEffect(() => { pausedRef.current = paused; }, [paused]);
  useEffect(() => {
    let source;
    let closed = false;
    let retryTimer;
    let staged = [];
    function append(line) {
      if (pausedRef.current) { staged.push(line); setPending(staged.length); return; }
      if (staged.length) { line = staged.splice(0).concat(line); setPending(0); }
      const add = Array.isArray(line) ? line : [line];
      setLines(prev => prev.concat(add).slice(-bufferLimit));
    }
    function connect() {
      setStatus(reconnectRef.current ? 'Reconnecting' : 'Connecting');
      source = new EventSource(`${API}/system/logs/stream?container=${encodeURIComponent(container)}&tail=${encodeURIComponent(tail)}`);
      source.addEventListener('ready', () => { reconnectRef.current = 0; setStatus('Connected'); setError(''); });
      source.addEventListener('heartbeat', () => setStatus('Connected'));
      source.addEventListener('log', event => { try { append(JSON.parse(event.data)); } catch { append({timestamp: new Date().toISOString(), container: 'unknown', level: 'ERROR', message: 'Malformed log line'}); } });
      source.addEventListener('error', event => {
        setStatus('Reconnecting');
        if (event.data) { try { setError(JSON.parse(event.data).message || 'Log stream error'); } catch { setError('Log stream error'); } }
        source?.close();
        if (!closed) {
          const delay = Math.min(30000, 1000 * (2 ** reconnectRef.current++));
          retryTimer = setTimeout(connect, delay);
        }
      });
    }
    connect();
    return () => { closed = true; clearTimeout(retryTimer); source?.close(); setStatus('Disconnected'); };
  }, [container, tail, bufferLimit]);
  return {lines, setLines, pending, status, error};
}

function levelTone(level) {
  if (level === 'ERROR' || level === 'CRITICAL') return 'server';
  if (level === 'WARNING') return 'warn';
  if (level === 'DEBUG') return 'muted';
  return 'ok';
}

function highlight(text, q) {
  if (!q) return text;
  const idx = text.toLowerCase().indexOf(q.toLowerCase());
  if (idx < 0) return text;
  return <>{text.slice(0, idx)}<mark>{text.slice(idx, idx + q.length)}</mark>{text.slice(idx + q.length)}</>;
}

function formatLogLine(line) {
  return `${line.timestamp || ''} ${line.container || ''} ${line.level || ''} ${line.message || ''}`;
}

function LandingPage({domain, setDomain, run, targets, loadTarget, runDisabled, runError, alert}) {
  const examples = ['example.com', 'app.example.com', 'https://target.com'];
  return <div className="landing-page">
    <nav className="landing-nav"><b>Recon Radar</b><button className="secondary" onClick={() => window.open('/logs', '_blank', 'noopener,noreferrer')}>View Logs</button></nav>
    <section className="landing-hero">
      <div className="landing-copy"><span className="eyebrow">Attack surface scanner</span><h1>Enter a target. Watch the surface resolve.</h1><p>Start with one domain and move into a focused scan workspace for subdomains, live hosts, content paths, screenshots, and raw output.</p></div>
      <form className="target-launcher" onSubmit={e => { e.preventDefault(); if (!runDisabled) run(); }}>
        <label>Target URL or domain</label>
        <div className="launcher-row"><input autoFocus value={domain} onChange={e => setDomain(e.target.value)} placeholder="example.com"/><button className="primary" disabled={runDisabled}>{runDisabled ? 'Fix options' : 'Start scan'}</button></div>
        {runError && <div className="inline-alert">{runError}</div>}
        {alert && <div className="alert">{alert}</div>}
        <div className="example-row"><span>Try</span>{examples.map(item => <button type="button" key={item} onClick={() => setDomain(item)}>{item}</button>)}</div>
      </form>
    </section>
    <section className="landing-recents"><div><h2>Recent targets</h2><p>Select a previous target to open its scan workspace.</p></div><div className="recent-grid">{targets.slice(0, 8).map(t => <button key={t.id} onClick={() => loadTarget(t)}><b>{t.domain}</b><span>{t.scan_count} scans</span></button>)}{!targets.length && <p className="muted">No targets yet. Your first scan will appear here.</p>}</div></section>
  </div>;
}

function LogsPage() {
  const [containers, setContainers] = useState([]);
  const [container, setContainer] = useState(localStorage.getItem('logs.container') || 'all');
  const [paused, setPaused] = useState(false);
  const [autoScroll, setAutoScroll] = useState(localStorage.getItem('logs.autoscroll') !== 'false');
  const [query, setQuery] = useState('');
  const [level, setLevel] = useState('All');
  const [tail, setTail] = useState(Number(localStorage.getItem('logs.tail') || 200));
  const [jump, setJump] = useState(false);
  const {lines, setLines, pending, status, error} = useContainerLogs({container, tail, paused, bufferLimit: 10000});
  const endRef = React.useRef(null);
  const scrollerRef = React.useRef(null);
  useEffect(() => { j(`${API}/system/logs/containers`).then(r => setContainers(r.containers || [])).catch(e => setContainers([{id: 'unavailable', display_name: e.message, status: 'error'}])); }, []);
  useEffect(() => { localStorage.setItem('logs.container', container); }, [container]);
  useEffect(() => { localStorage.setItem('logs.autoscroll', String(autoScroll)); }, [autoScroll]);
  useEffect(() => { localStorage.setItem('logs.tail', String(tail)); }, [tail]);
  useEffect(() => { if (autoScroll && !paused) endRef.current?.scrollIntoView({block: 'end'}); }, [lines, autoScroll, paused]);
  const visible = lines.filter(l => (container === 'all' || l.container === container) && (level === 'All' || l.level === level) && (!query || formatLogLine(l).toLowerCase().includes(query.toLowerCase())));
  const rendered = visible.slice(-1000);
  function copyVisible() { navigator.clipboard?.writeText(visible.map(formatLogLine).join('\n')); }
  function downloadVisible() { const blob = new Blob([visible.map(formatLogLine).join('\n')], {type: 'text/plain'}); const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = `container-logs-${container}.txt`; a.click(); URL.revokeObjectURL(a.href); }
  function onScroll() { const el = scrollerRef.current; if (!el) return; const nearBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 48; if (!nearBottom) { setAutoScroll(false); setJump(true); } else setJump(false); }
  function reconnect() { window.location.reload(); }
  return <div className="logs-page"><div className="logs-toolbar"><div><h1>Live Container Logs</h1><p>Docker Compose infrastructure logs. Content is redacted server-side and rendered as plain text.</p></div><Badge tone={status === 'Connected' ? 'ok' : status === 'Reconnecting' ? 'warn' : 'server'}>{status}</Badge><button onClick={reconnect}>Reconnect</button></div>
    {error && <div className="inline-alert">{error}</div>}
    <div className="logs-toolbar sticky"><label>Container <select value={container} onChange={e => setContainer(e.target.value)}><option value="all">All containers</option>{containers.map(c => <option key={c.id} value={c.id}>{c.display_name} ({c.status})</option>)}</select></label><input className="wide" placeholder="Search/filter logs" value={query} onChange={e => setQuery(e.target.value)}/><label>Level <select value={level} onChange={e => setLevel(e.target.value)}>{['All','DEBUG','INFO','WARNING','ERROR','CRITICAL'].map(x => <option key={x}>{x}</option>)}</select></label><label>Tail <input type="number" min="0" max="2000" value={tail} onChange={e => setTail(Math.min(2000, Math.max(0, Number(e.target.value) || 0)))}/></label><button onClick={() => setPaused(!paused)}>{paused ? `Resume${pending ? ` (${pending})` : ''}` : 'Pause'}</button><button onClick={() => setLines([])}>Clear</button><label><input type="checkbox" checked={autoScroll} onChange={e => setAutoScroll(e.target.checked)}/> Auto-scroll</label><button onClick={copyVisible}>Copy visible logs</button><button onClick={downloadVisible}>Download</button><span>{visible.length} visible / {lines.length} buffered</span></div>
    <div className="logs-shell" ref={scrollerRef} onScroll={onScroll}>{rendered.map((line, idx) => <div className={`container-log-line c-${line.container}`} key={`${line.timestamp}-${idx}`}><span className="log-time">{line.timestamp}</span><span className="container-badge">{line.container}</span><Badge tone={levelTone(line.level)}>{line.level}</Badge><span className="log-message">{highlight(line.message || '', query)}</span></div>)}<div ref={endRef}/></div>{jump && <button className="jump-latest" onClick={() => { setAutoScroll(true); setJump(false); endRef.current?.scrollIntoView(); }}>Jump to latest</button>}
  </div>;
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
  const [health, setHealth] = useState(null);
  const [selectedIds, setSelectedIds] = useState(new Set());
  const [detail, setDetail] = useState(null);
  const [alert, setAlert] = useState('');
  const [opts, setOpts] = useState({recursion_depth: 2, ffuf_threads: 20, ffuf_match_codes: 'all', ffuf_recursive: false, ffuf_auto_calibration: true, ffuf_baseline_count: 3, ffuf_host_timeout: 300, run_ffuf: true, run_screenshots: true});

  const refresh = async () => {
    const [targetRows, wordlistRows, appSettings, healthInfo] = await Promise.all([j(`${API}/targets`), j(`${API}/wordlists`), j(`${API}/settings`), j(`${API}/health`)]);
    setTargets(targetRows); setWordlists(wordlistRows); setSettings(appSettings); setHealth(healthInfo);
    if (active) setResult(await j(`${API}/targets/${active.id}/results`));
  };
  useEffect(() => { refresh(); }, []);
  usePoll(scan?.id, refresh);

  async function run() {
    setAlert('');
    try {
      const payload = {domain, ...opts, subdomain_wordlist_id: opts.subdomain_wordlist_id ? Number(opts.subdomain_wordlist_id) : null, dirb_wordlist_id: opts.dirb_wordlist_id ? Number(opts.dirb_wordlist_id) : null};
      const res = await j(`${API}/scans/run`, {method: 'POST', body: JSON.stringify(payload)});
      setScan({id: res.scan_id}); setActive({id: res.target_id, domain}); await refresh();
    } catch (err) {
      setAlert(err.message || String(err));
    }
  }
  async function loadTarget(t) { setActive(t); setDomain(t.domain); setResult(await j(`${API}/targets/${t.id}/results`)); }
  async function deleteTarget(t) {
    const ok = window.confirm(`Delete target ${t.domain} and all scans/results/raw-output references for it? This cannot be undone.`);
    if (!ok) return;
    await j(`${API}/targets/${t.id}`, {method: 'DELETE'});
    if (active?.id === t.id) { setActive(null); setResult(null); setDetail(null); }
    await refresh();
  }
  async function upload(kind, file) { if (!file) return; setAlert(''); try { const fd = new FormData(); fd.append('file', file); await j(`${API}/wordlists/${kind}`, {method: 'POST', body: fd}); await refresh(); } catch (err) { setAlert(err.message || String(err)); } }
  async function saveSettings() { setAlert(''); try { const body = {...settings, headers: Object.fromEntries((settings.headerLines || '').split('\n').filter(Boolean).map(l => { const [k, ...v] = l.split(':'); return [k.trim(), v.join(':').trim()]; }))}; delete body.headerLines; setSettings(await j(`${API}/settings`, {method: 'PUT', body: JSON.stringify(body)})); } catch (err) { setAlert(err.message || String(err)); } }
  async function markInteresting(kind, row) { await j(`${API}/${kind}/${row.id}/interesting`, {method: 'PATCH', body: JSON.stringify({interesting: !row.interesting, note: row.note || '', tag: row.tag || ''})}); await refresh(); }
  const toggleSelected = (id, checked) => setSelectedIds(prev => { const next = new Set(prev); checked ? next.add(id) : next.delete(id); return next; });

  const httpRows = result?.http || [];
  const http200 = httpRows.filter(h => h.status_code === 200);
  const httpOther = httpRows.filter(h => h.status_code !== 200);
  const subdomainRows = (result?.subdomains || []).map(s => ({...s, url: s.name}));
  const dirRows = result?.dirs || [];
  const scanStatus = result?.active_scan || scan;
  const scanRunning = ['queued', 'running'].includes(scanStatus?.status);
  const defaultFfuf = health?.ffuf;
  const defaultAvailable = Boolean(defaultFfuf?.default_wordlist_available);
  const defaultName = defaultFfuf?.default_wordlist_name || 'common.txt';
  const defaultLabel = defaultName === 'common.txt' ? 'SecLists common.txt' : defaultName;
  const runError = opts.run_ffuf && !opts.dirb_wordlist_id && health && !defaultAvailable ? 'FFUF is enabled, but no selected or default directory wordlist is available.' : '';
  const ffufWordlistHint = opts.run_ffuf && !opts.dirb_wordlist_id && defaultAvailable ? `${defaultLabel} will be used automatically.` : '';
  const runDisabled = Boolean(runError) || scanRunning || !domain.trim();

  if (!active && !result && !scan) {
    return <LandingPage domain={domain} setDomain={setDomain} run={run} targets={targets} loadTarget={loadTarget} runDisabled={runDisabled} runError={runError} alert={alert}/>;
  }

  return <div className="app-shell">
    <Header domain={domain} setDomain={setDomain} run={run} result={result} targets={targets} loadTarget={loadTarget} runDisabled={runDisabled} runError={runError}/>{alert && <div className="alert">{alert}</div>}
    <main className="layout"><aside className="sidebar">
      <SidebarGroup title="Marked Targets"><p className="muted">Mark rows during review. Target pinning is next.</p></SidebarGroup>
      <SidebarGroup title="Recent Targets">{targets.map(t => <div className="target-row" key={t.id}><button className="target" onClick={() => loadTarget(t)}>{t.domain}<span>{t.scan_count} scans</span></button><button className="danger small" title={`Delete ${t.domain}`} onClick={() => deleteTarget(t)}>Delete</button></div>)}</SidebarGroup>
      <SidebarGroup title="Scan History">{(result?.scans || []).map(s => <button className="target scan-history-item" key={s.id} onClick={() => j(`${API}/targets/${active.id}/results?scan_id=${s.id}`).then(setResult)}><b>Scan #{s.id}</b><span>{ago(s.created_at)} · {s.status}</span></button>)}</SidebarGroup>
      <SidebarGroup title="Wordlists"><label>Subdomain upload<input type="file" onChange={e => upload('subdomain', e.target.files[0])}/></label><label>Dirb upload<input type="file" onChange={e => upload('dirb', e.target.files[0])}/></label><select onChange={e => setOpts({...opts, subdomain_wordlist_id: e.target.value})}><option value="">Subdomain wordlist</option>{wordlists.filter(w => w.kind === 'subdomain').map(w => <option key={w.id} value={w.id}>{w.name}</option>)}</select><select value={opts.dirb_wordlist_id || ''} onChange={e => setOpts({...opts, dirb_wordlist_id: e.target.value})}><option value="">Default — {defaultLabel}</option>{wordlists.filter(w => w.kind === 'dirb').map(w => <option key={w.id} value={w.id}>{w.name}</option>)}</select>{ffufWordlistHint && <p className="hint">{ffufWordlistHint}</p>}{!defaultAvailable && opts.run_ffuf && !opts.dirb_wordlist_id && health && <p className="inline-alert">Default FFUF wordlist unavailable. Upload/select a dirb wordlist.</p>}</SidebarGroup>
      <SidebarGroup title="Request Settings" defaultOpen={false}>{settings && <><input value={settings.user_agent || ''} onChange={e => setSettings({...settings, user_agent: e.target.value})} placeholder="User-Agent"/><input value={settings.proxy || ''} onChange={e => setSettings({...settings, proxy: e.target.value})} placeholder="Proxy"/><textarea placeholder="Header: value per line" value={settings.headerLines ?? Object.entries(settings.headers || {}).map(([k, v]) => `${k}: ${v}`).join('\n')} onChange={e => setSettings({...settings, headerLines: e.target.value})}/><button onClick={saveSettings}>Save settings</button></>}</SidebarGroup>
      <SidebarGroup title="FFUF Options" defaultOpen={false}><label><input type="checkbox" checked={opts.run_ffuf} onChange={e => setOpts({...opts, run_ffuf: e.target.checked})}/> Run directory discovery</label>{runError && <p className="inline-alert">{runError}</p>}<input placeholder="extensions php,txt" onChange={e => setOpts({...opts, extensions: e.target.value})}/><input placeholder="match codes" value={opts.ffuf_match_codes} onChange={e => setOpts({...opts, ffuf_match_codes: e.target.value})}/><input placeholder="host timeout seconds" value={opts.ffuf_host_timeout} onChange={e => setOpts({...opts, ffuf_host_timeout: e.target.value})}/><label><input type="checkbox" checked={opts.ffuf_auto_calibration} onChange={e => setOpts({...opts, ffuf_auto_calibration: e.target.checked})}/> Auto calibration (-ac)</label><label><input type="checkbox" checked={opts.ffuf_recursive} onChange={e => setOpts({...opts, ffuf_recursive: e.target.checked})}/> Recursive</label></SidebarGroup>
      <SidebarGroup title="Import / Export" defaultOpen={false}><button onClick={() => active && window.open(`${API}/targets/${active.id}/export?format=json`, '_blank')}>Export JSON</button><button onClick={() => active && window.open(`${API}/targets/${active.id}/export?format=csv`, '_blank')}>Export CSV</button></SidebarGroup>
    </aside>
    <section className="workspace"><SummaryCards result={result}/><ProgressPanel scan={scanStatus} result={result}/><div className="tabs">{TABS.map(t => <button className={tab === t ? 'sel' : ''} onClick={() => setTab(t)} key={t}>{t} <span>{t === 'Subdomains' ? subdomainRows.length : t === 'Live Hosts' ? httpRows.length : t === 'Content Paths' ? dirRows.length : t === 'Screenshots' ? (result?.screenshots || []).length : (result?.raw || []).length}</span></button>)}<div className="export-buttons"><button onClick={() => active && window.open(`${API}/targets/${active.id}/export?format=json`, '_blank')}>Export JSON</button><button onClick={() => active && window.open(`${API}/targets/${active.id}/export?format=csv`, '_blank')}>Export CSV</button></div></div>
      {tab === 'Subdomains' && <AssetTable rows={subdomainRows} kind="subdomains" selectRow={setDetail} selectedIds={selectedIds} toggleSelected={toggleSelected} markInteresting={markInteresting}/>} 
      {tab === 'Live Hosts' && <><h3>200 OK</h3><AssetTable rows={http200} kind="http" selectRow={setDetail} selectedIds={selectedIds} toggleSelected={toggleSelected} markInteresting={markInteresting}/><h3>Other Status Codes</h3><AssetTable rows={httpOther} kind="http" selectRow={setDetail} selectedIds={selectedIds} toggleSelected={toggleSelected} markInteresting={markInteresting}/></>} 
      {tab === 'Content Paths' && <AssetTable rows={dirRows} kind="dirs" selectRow={setDetail} selectedIds={selectedIds} toggleSelected={toggleSelected} markInteresting={markInteresting}/>} 
      {tab === 'Screenshots' && <ScreenshotGallery rows={result?.screenshots || []} selectRow={setDetail} markInteresting={markInteresting}/>} 
      {tab === 'Raw Logs' && <RawConsole rows={result?.raw || []}/>} 
    </section><DetailsPanel row={detail} result={result} close={() => setDetail(null)} markInteresting={markInteresting}/></main>
  </div>;
}

createRoot(document.getElementById('root')).render(window.location.pathname === '/logs' ? <LogsPage/> : <App/>);
