import React, {useCallback, useEffect, useMemo, useRef, useState} from 'react';
import {createRoot} from 'react-dom/client';
import './style.css';

const API = '/api';
const TABS = ['Subdomains', 'Live Hosts', 'Content Paths', 'Vulnerabilities', 'JS Intel', 'Parameters', 'Arjun', 'Screenshots', 'Raw Logs'];
const INTERESTING_STATUS_CODES = new Set([200, 204, 301, 302, 401, 403, 500]);
const DEFAULT_SCAN_OPTS = {
  recursion_depth: 2,
  ffuf_threads: 20,
  ffuf_match_codes: 'all',
  ffuf_mode: 'tech',
  ffuf_recursive: false,
  ffuf_auto_calibration: true,
  ffuf_baseline_count: 3,
  ffuf_host_timeout: 300,
  run_naabu: true,
  naabu_ports: '80,81,3000,3001,5000,5173,7001,8000,8008,8080,8081,8443,8888,9000,9443,10443',
  subfinder_recursive: false,
  use_crtsh: false,
  use_cached_subdomains: true,
  refresh_passive_subdomains: true,
  fresh_subdomain_scan: false,
  run_amass: false,
  amass_timeout: 600,
  wappalyzer_scan_type: 'balanced',
  wappalyzer_workers: 5,
  run_ffuf: true,
  run_js_intel: true,
  js_intel_max_hosts: 80,
  js_intel_max_scripts_per_host: 25,
  js_intel_max_bytes: 2000000,
  js_intel_timeout: 180,
  trufflehog_results: 'verified,unknown,unverified',
  trufflehog_concurrency: 4,
  run_nuclei: true,
  nuclei_profile: 'light',
  nuclei_severity: 'high,critical',
  nuclei_tags: '',
  nuclei_exclude_tags: 'dos,fuzz,intrusive',
  nuclei_templates: '',
  nuclei_concurrency: 10,
  nuclei_rate_limit: 25,
  nuclei_timeout: 4,
  nuclei_retries: 0,
  nuclei_stage_timeout: 600,
  nuclei_max_urls: 100,
  run_parameters: true,
  katana_depth: 2,
  run_katana_headless: false,
  parameter_timeout: 240,
  katana_crawl_duration: '2m',
  run_arjun: false,
  arjun_methods: 'GET',
  arjun_timeout: 240,
  arjun_threads: 5,
  arjun_request_timeout: 10,
  arjun_stable: true,
  run_screenshots: true,
  use_subdomains_top1million_110000: false,
  use_bug_bounty_subdomains_trickest: false,
};

function loadStoredScanOpts() {
  try {
    return {...DEFAULT_SCAN_OPTS, ...JSON.parse(localStorage.getItem('scan.options') || '{}')};
  } catch {
    return DEFAULT_SCAN_OPTS;
  }
}

async function j(url, options = {}) {
  const isForm = options.body instanceof FormData;
  const headers = isForm ? (options.headers || {}) : {'Content-Type': 'application/json', ...(options.headers || {})};
  const r = await fetch(url, {...options, headers});
  const contentType = r.headers.get('content-type') || '';
  const body = contentType.includes('application/json') ? await r.json() : await r.text();
  if (!r.ok) throw new Error(body?.detail || body || `Request failed: ${r.status}`);
  return body;
}

function usePoll(scanId, onTick, enabled = true) {
  const onTickRef = useRef(onTick);
  const inFlightRef = useRef(false);
  useEffect(() => { onTickRef.current = onTick; }, [onTick]);
  useEffect(() => {
    if (!scanId || !enabled) return;
    const id = setInterval(async () => {
      if (inFlightRef.current) return;
      inFlightRef.current = true;
      try {
        await onTickRef.current?.();
      } finally {
        inFlightRef.current = false;
      }
    }, 3000);
    return () => clearInterval(id);
  }, [scanId, enabled]);
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
  const haystack = `${row.url || row.source_url || row.matched_at || row.name || ''} ${row.title || row.template_name || row.description || ''} ${(row.tech || []).join(' ')} ${(row.tags || []).join(' ')}`.toLowerCase();
  const tags = [];
  if (row.is_new) tags.push('New');
  if (row.interesting) tags.push('Marked');
  if (row.open_directory) tags.push('Index of');
  if (row.confidence === 'confirmed') tags.push('Confirmed');
  if (row.confidence === 'possible') tags.push('Possible');
  if (row.confidence === 'filtered') tags.push('Filtered');
  if (INTERESTING_STATUS_CODES.has(Number(row.status_code))) tags.push('Interesting Status');
  if (row.suspicious) tags.push('Suspicious Param');
  if (row.finding_type) tags.push(row.finding_type);
  if (row.template_id) tags.push('Nuclei');
  if (row.severity === 'critical') tags.push('Critical');
  if (row.severity === 'high') tags.push('High Signal');
  if (row.severity === 'medium') tags.push('Review');
  if ((row.tags || []).includes('source-sink')) tags.push('Source → Sink');
  if ((row.tags || []).includes('secret')) tags.push('Secret');
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

function Drawer({title, open, onClose, children, wide = false}) {
  if (!open) return null;
  return <div className="drawer-backdrop" onMouseDown={onClose}>
    <aside className={`drawer ${wide ? 'wide' : ''}`} role="dialog" aria-modal="true" aria-label={title} onMouseDown={e => e.stopPropagation()}>
      <div className="drawer-head"><h2>{title}</h2><button className="close" onClick={onClose}>Close</button></div>
      <div className="drawer-body">{children}</div>
    </aside>
  </div>;
}

function TargetLoadingScreen({target}) {
  if (!target) return null;
  return <div className="target-loading-screen" role="dialog" aria-modal="true" aria-labelledby="target-loading-title" aria-live="polite">
    <div className="target-loading-card">
      <div className="target-loading-spinner" aria-hidden="true"><span /></div>
      <span className="eyebrow">Opening workspace</span>
      <h2 id="target-loading-title">Loading {target.domain}</h2>
      <p>Fetching this target’s scans and results. Other targets remain unloaded.</p>
      <div className="target-loading-progress" aria-label="Loading target data"><span /></div>
      <small>Please keep this screen open.</small>
    </div>
  </div>;
}

function SummaryCards({result}) {
  const http = result?.http || [];
  const subdomains = result?.subdomains?.length || 0;
  const newSubdomains = result?.stage_statuses?.subdomains?.new || 0;
  const cachedSubdomains = result?.stage_statuses?.subdomains?.cached || 0;
  const live = http.filter(h => h.status_code && h.status_code < 500).length;
  const screenshots = result?.screenshots?.length || 0;
  const dirs = result?.dirs || [];
  const jsFindings = result?.js_findings || [];
  const nucleiFindings = result?.nuclei_findings || [];
  const jsHigh = jsFindings.filter(j => j.severity === 'high').length;
  const nucleiCritical = nucleiFindings.filter(n => n.severity === 'critical').length;
  const nucleiHigh = nucleiFindings.filter(n => n.severity === 'high').length;
  const confirmedDirs = dirs.filter(d => d.confidence === 'confirmed').length;
  const possibleDirs = dirs.filter(d => d.confidence === 'possible').length;
  const filteredDirs = dirs.filter(d => d.confidence === 'filtered').length;
  const interesting = [...(result?.subdomains || []), ...http, ...(result?.dirs || []), ...nucleiFindings, ...(result?.screenshots || [])].filter(r => r.interesting).length;
  const takeoverHints = http.filter(h => /github|heroku|netlify|s3|azure|cloudfront/i.test(`${h.title || ''} ${(h.tech || []).join(' ')}`)).length + jsHigh + nucleiHigh + nucleiCritical;
  const ips = new Set(http.map(h => h.ip).filter(Boolean)).size;
  const ports = new Set(http.flatMap(h => h.ports || [])).size;
  const uniqueTech = new Set(http.flatMap(h => compactTech(h.tech))).size;
  const cdns = http.filter(h => /cloudflare|cloudfront|akamai|fastly/i.test((h.tech || []).join(' '))).length;
  return <>
    <div className="cards compact-cards">
      <div className="card"><span className="card-label">DNS</span><b>{subdomains}</b><span>Subdomains</span><small>{newSubdomains} new · {cachedSubdomains} cached</small></div>
      <div className="card"><span className="card-label">HTTP</span><b>{live}</b><span>Live hosts</span></div>
      <div className="card"><span className="card-label">VISUAL</span><b>{screenshots}</b><span>Screenshots</span></div>
      <div className="card"><span className="card-label">PATHS</span><b>{confirmedDirs}</b><span>Content paths</span><small>{possibleDirs} possible · {filteredDirs} filtered</small></div>
      <div className="card hot"><span className="card-label">MARKED</span><b>{interesting}</b><span>Marked</span></div>
      <div className="card warn"><span className="card-label">RISK</span><b>{takeoverHints}</b><span>Takeover / JS hints</span><small>{jsHigh} high JS</small></div>
      <div className="card hot"><span className="card-label">NUCLEI</span><b>{nucleiFindings.length}</b><span>Vulnerabilities</span><small>{nucleiCritical} critical · {nucleiHigh} high</small></div>
    </div>
    <div className="infra-stats"><Badge>IPs {ips}</Badge><Badge>Ports {ports}</Badge><Badge>Unique Tech {uniqueTech}</Badge><Badge>CDNs {cdns}</Badge><Badge>Cloud Providers {http.filter(h => /aws|azure|gcp|cloudflare/i.test((h.tech || []).join(' '))).length}</Badge></div>
  </>;
}

function ProgressPanel({scan, result}) {
  const stage = scan?.stage || 'queued';
  const status = scan?.status || 'idle';
  const stageInfo = result?.stage_statuses || {};
  const http = result?.http || [];
  const totalHosts = result?.subdomains?.length || 0;
  const subdomainStage = stageInfo.subdomains || {};
  const liveHosts = http.length;
  const taggedHosts = http.filter(h => (h.tech || []).length).length;
  const dirs = result?.dirs || [];
  const parameters = result?.parameters || [];
  const jsFindings = result?.js_findings || [];
  const nucleiFindings = result?.nuclei_findings || [];
  const highJsFindings = jsFindings.filter(j => j.severity === 'high').length;
  const highNuclei = nucleiFindings.filter(n => ['high', 'critical'].includes(n.severity)).length;
  const confirmed = dirs.filter(d => d.confidence === 'confirmed').length;
  const possible = dirs.filter(d => d.confidence === 'possible').length;
  const filtered = dirs.filter(d => d.confidence === 'filtered').length;
  const screenshotCount = result?.screenshots?.length || 0;
  const stages = [
    ['subdomains', 'Subdomains', `${totalHosts} total · ${subdomainStage.new || 0} new · ${subdomainStage.cached || 0} cached`],
    ['naabu', 'Naabu', `${result?.ports?.length || 0} ports`],
    ['httpx', 'Httpx', `${liveHosts}/${totalHosts || '—'}`],
    ['wappalyzer', 'Wappalyzer', `${taggedHosts} tagged`],
    ['js_intel', 'JS Intel', `${jsFindings.length} findings · ${highJsFindings} high`],
    ['ffuf', 'FFUF', `${stageInfo.ffuf?.successful_hosts || 0}/${stageInfo.ffuf?.total || liveHosts || '—'} hosts · ${confirmed} confirmed · ${possible} possible · ${filtered} filtered · ${stageInfo.ffuf?.failed_hosts || 0} failed`],
    ['nuclei', 'Nuclei', `${nucleiFindings.length} findings · ${highNuclei} high/critical`],
    ['parameters', 'Parameters', `${parameters.length} params · ${stageInfo.parameters?.suspicious || 0} suspicious`],
    ['screenshots', 'Gowitness', `${screenshotCount} shots`],
  ];
  if (status === 'complete' || status === 'partial') {
    return <div className={`progress-panel compact ${status === 'partial' ? 'partial' : ''}`}>
      <div className="pipeline-summary">
        <span>Scan pipeline</span>
        <Badge tone={status === 'partial' ? 'warn' : 'ok'}>{status}</Badge>
        <em>{totalHosts} subdomains</em>
        <em>{result?.ports?.length || 0} ports</em>
        <em>{liveHosts} live</em>
        <em>{taggedHosts} tagged</em>
        <em>{jsFindings.length} JS</em>
        <em>{nucleiFindings.length} nuclei</em>
        <em>{confirmed} paths</em>
        <em>{parameters.length} params</em>
        <em>{screenshotCount} shots</em>
        <strong>{scan?.progress || 100}%</strong>
      </div>
      {scan?.error && <div className="inline-alert">{scan.error}</div>}
    </div>;
  }
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

function Header({domain, setDomain, run, stopScan, result, targets, loadTarget, runDisabled, runError, openTargets, openSettings}) {
  const scan = result?.active_scan;
  const target = result?.target?.domain || 'No target selected';
  const counts = `${result?.subdomains?.length || 0} subdomains | ${(result?.http || []).length} live results | ${result?.dirs?.length || 0} content paths | ${result?.nuclei_findings?.length || 0} vulns | ${result?.parameters?.length || 0} params`;
  const activeScan = ['queued', 'running', 'stopping'].includes(scan?.status);
  return <header>
    <div className="brand"><h1>{target}</h1><div className="header-meta"><Badge tone={scan?.status === 'complete' ? 'ok' : 'redirect'}>{scan?.status || 'ready'}</Badge><span>{counts}</span><span>Started: {ago(scan?.started_at || scan?.created_at)}</span></div></div>
    <div className="runbox"><select onChange={e => { const t = targets.find(x => String(x.id) === e.target.value); if (t) loadTarget(t); }}><option>Recent targets</option>{targets.slice(0, 12).map(t => <option key={t.id} value={t.id}>{t.domain}</option>)}</select><input className="target-input" value={domain} onChange={e => setDomain(e.target.value)} placeholder="example.com"/><button className="secondary" onClick={openTargets}>Targets</button><button className="secondary" onClick={openSettings}>Settings</button><button className="secondary" title="Open live container logs" onClick={() => window.open('/logs', '_blank', 'noopener,noreferrer')}>View Logs</button>{activeScan && <button className="danger" disabled={scan?.status === 'stopping'} onClick={stopScan}>{scan?.status === 'stopping' ? 'Stopping…' : 'Stop scan'}</button>}<button className="primary" disabled={runDisabled} title={runError || ''} onClick={run}>{runDisabled ? 'Fix options' : 'Run scan'}</button></div>{runError && <div className="inline-alert">{runError}</div>}
  </header>;
}

function Filters({filters, setFilters}) {
  const chips = ['Alive', 'Interesting Status', 'Interesting', 'Suspicious Param', 'APIs', 'Login', 'Admin', 'GraphQL', 'Swagger', 'Takeover'];
  const toggleChip = chip => setFilters({...filters, chips: filters.chips.includes(chip) ? filters.chips.filter(c => c !== chip) : [...filters.chips, chip]});
  return <>
    <div className="filters compact-filters">
      <input className="wide" placeholder="/ Search host, title, tech, IP, tag..." value={filters.q} onChange={e => setFilters({...filters, q: e.target.value})}/>
      <input placeholder="Host / URL" value={filters.host} onChange={e => setFilters({...filters, host: e.target.value})}/>
      <input placeholder="Status e.g. 200, 403" value={filters.status} onChange={e => setFilters({...filters, status: e.target.value})}/>
      <input placeholder="Title / Path / Finding" value={filters.title} onChange={e => setFilters({...filters, title: e.target.value})}/>
      <input placeholder="Technology" value={filters.tech} onChange={e => setFilters({...filters, tech: e.target.value})}/>
      <input placeholder="IP / ASN" value={filters.ip} onChange={e => setFilters({...filters, ip: e.target.value})}/>
      <input placeholder="Source" value={filters.source} onChange={e => setFilters({...filters, source: e.target.value})}/>
      <input placeholder="Tags" value={filters.tags} onChange={e => setFilters({...filters, tags: e.target.value})}/>
      <input placeholder="Confidence / Severity" value={filters.confidence} onChange={e => setFilters({...filters, confidence: e.target.value})}/>
    </div>
    <div className="filter-chips">{chips.map(chip => <button key={chip} className={filters.chips.includes(chip) ? 'chip active' : 'chip'} onClick={() => toggleChip(chip)}>{chip}</button>)}</div>
  </>;
}

function applyFilters(rows, filters) {
  return rows.filter(row => {
    const blob = JSON.stringify({...row, tags: tagsFor(row)}).toLowerCase();
    const value = String(row.url || row.source_url || row.matched_at || row.name || '').toLowerCase();
    const title = String(row.title || row.template_name || row.path || row.param || row.indicator || row.template_id || row.reason || row.evidence || row.description || '').toLowerCase();
    const source = String((row.sources || []).join(', ') || row.source || row.finding_type || row.template_id || row.base_url || '').toLowerCase();
    const tagBlob = tagsFor(row).join(' ').toLowerCase();
    const confidence = String(row.confidence || row.severity || '').toLowerCase();
    return (!filters.q || blob.includes(filters.q.toLowerCase())) &&
      (!filters.host || value.includes(filters.host.toLowerCase())) &&
      (!filters.status || String(row.status_code || '').includes(filters.status)) &&
      (!filters.title || title.includes(filters.title.toLowerCase())) &&
      (!filters.tech || blob.includes(filters.tech.toLowerCase())) &&
      (!filters.ip || String(row.ip || '').includes(filters.ip)) &&
      (!filters.source || source.includes(filters.source.toLowerCase())) &&
      (!filters.tags || tagBlob.includes(filters.tags.toLowerCase())) &&
      (!filters.confidence || confidence.includes(filters.confidence.toLowerCase())) &&
      (!filters.chips.includes('Interesting') || row.interesting) &&
      (!filters.chips.includes('Interesting Status') || INTERESTING_STATUS_CODES.has(Number(row.status_code))) &&
      (!filters.chips.includes('Suspicious Param') || row.suspicious) &&
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
  const [filters, setFilters] = useState({q: '', host: '', status: '', title: '', tech: '', ip: '', source: '', tags: '', confidence: '', chips: []});
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);
  const filtered = useMemo(() => applyFilters(rows, filters), [rows, filters]);
  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const safePage = Math.min(page, totalPages);
  const visible = filtered.slice((safePage - 1) * pageSize, safePage * pageSize);
  useEffect(() => { setPage(1); }, [filters, kind]);
  const copy = value => navigator.clipboard?.writeText(value).catch(() => {});
  return <>
    <Filters filters={filters} setFilters={setFilters}/>
    <div className="bulkbar"><label><input type="checkbox" onChange={e => visible.forEach(r => toggleSelected(r.id, e.target.checked))}/> Select page</label><span>{selectedIds.size} selected</span><button onClick={() => copy(filtered.filter(r => selectedIds.has(r.id)).map(r => r.url || r.source_url || r.name || r.matched_at).filter(Boolean).join('\n'))}>Copy selected</button><div className="pager"><button disabled={safePage <= 1} onClick={() => setPage(safePage - 1)}>Prev</button><span>Page {safePage} / {totalPages} · {filtered.length} results</span><button disabled={safePage >= totalPages} onClick={() => setPage(safePage + 1)}>Next</button><select value={pageSize} onChange={e => { setPageSize(Number(e.target.value)); setPage(1); }}><option value="50">50/page</option><option value="100">100/page</option><option value="250">250/page</option></select></div></div>
    <div className="table-wrap"><table className="asset-table"><colgroup><col className="col-select"/><col className="col-host"/><col className="col-status"/><col className="col-title"/><col className="col-ip"/><col className="col-tech"/><col className="col-source"/><col className="col-tags"/><col className="col-confidence"/><col className="col-actions"/></colgroup><thead><tr><th></th><th>Host</th><th>Status</th><th>Title</th><th>IP</th><th>Tech</th><th>Source</th><th>Tags</th><th>Confidence</th><th>Actions</th></tr></thead><tbody>{visible.map(row => {
      const value = row.url || row.source_url || row.matched_at || row.name;
      const tags = tagsFor(row);
      return <tr key={`${kind}-${row.id}`} onClick={() => selectRow({...row, kind})} className={row.is_new ? 'new' : ''}>
        <td onClick={e => e.stopPropagation()}><input type="checkbox" checked={selectedIds.has(row.id)} onChange={e => toggleSelected(row.id, e.target.checked)}/></td>
        <td title={value}><div className="host-cell">{faviconFor(value)}<div><b>{hostFromUrl(value)}</b><div className="subtext">{value}</div></div></div></td>
        <td>{row.status_code ? <Badge tone={statusClass(row.status_code)}>{row.status_code}</Badge> : <span className="muted">—</span>}</td>
        <td title={[row.title || row.template_name || row.path || row.param || row.indicator || row.template_id || '', row.reason || row.evidence || row.description || ''].filter(Boolean).join('\n')}><div className="cell-main">{row.title || row.template_name || row.path || row.param || row.indicator || row.template_id || <span className="muted">—</span>}</div><div className="subtext">{row.reason || row.evidence || row.description || ''}</div></td>
        <td>{row.ip || (row.line ? `Line ${row.line}` : <span className="muted">—</span>)}<div className="subtext">{(row.ports || []).length ? `Ports ${(row.ports || []).join(', ')}` : row.column ? `Column ${row.column}` : ''}</div></td>
        <td>{row.finding_type ? <TechBadges tech={[row.finding_type, ...(row.tags || [])]} /> : row.template_id ? <TechBadges tech={[row.type || 'nuclei', ...(row.tags || [])]} /> : <TechBadges tech={[...(row.fingerprints || []), ...(row.tech || [])]} />}</td>
        <td title={(row.sources || []).join(', ') || row.source || row.finding_type || row.template_id || row.base_url || ''}><div className="cell-main">{(row.sources || []).join(', ') || row.source || row.finding_type || row.template_id || row.base_url || <span className="muted">—</span>}</div></td>
        <td>{tags.length ? tags.map(t => <Badge key={t} tone={t === 'Marked' ? 'hot' : t === 'Filtered' ? 'client' : t === 'Possible' ? 'warn' : t === 'Confirmed' ? 'ok' : 'muted'}>{t}</Badge>) : <span className="muted">—</span>}</td>
        <td>{row.severity ? <Badge tone={row.severity === 'critical' || row.severity === 'high' ? 'server' : row.severity === 'medium' ? 'warn' : 'muted'}>{row.severity}</Badge> : row.confidence ? <Badge tone={row.confidence === 'confirmed' ? 'ok' : row.confidence === 'possible' ? 'warn' : row.confidence === 'filtered' ? 'client' : 'muted'}>{row.confidence}</Badge> : <span className="muted">—</span>}<div className="subtext">{row.confidence && row.severity ? row.confidence : ''}{row.size ? `${row.size} B` : ''}{row.words ? ` · ${row.words}w` : ''}</div></td>
        <td className="actions" onClick={e => e.stopPropagation()}><button onClick={() => window.open(value, '_blank')}>Open</button><button onClick={() => copy(value)}>Copy</button><button onClick={() => markInteresting(kind, row)}>Mark</button><button title="Screenshot">Shot</button><button title="Run nuclei">Nuclei</button></td>
      </tr>;
    })}</tbody></table></div>
  </>;
}

function ScreenshotGallery({rows, selectRow, markInteresting}) {
  const [lightboxIndex, setLightboxIndex] = useState(null);
  const current = lightboxIndex == null ? null : rows[lightboxIndex];
  const close = useCallback(() => setLightboxIndex(null), []);
  const move = useCallback(delta => setLightboxIndex(index => {
    if (index == null || !rows.length) return index;
    return (index + delta + rows.length) % rows.length;
  }), [rows.length]);
  useEffect(() => {
    if (lightboxIndex == null) return;
    function onKey(e) {
      if (e.key === 'Escape') close();
      if (e.key === 'ArrowRight') move(1);
      if (e.key === 'ArrowLeft') move(-1);
    }
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [lightboxIndex, close, move]);
  return <>
    <div className="gallery">{rows.map((s, index) => <figure key={s.id} onClick={() => selectRow({...s, kind: 'screenshots'})}><button className="shot-preview" onClick={e => { e.preventDefault(); e.stopPropagation(); setLightboxIndex(index); }}><img src={s.image_url} alt={`Screenshot of ${s.url}`}/></button><figcaption><b>{hostFromUrl(s.url)}</b><div><Badge tone="ok">Screenshot</Badge>{s.interesting && <Badge tone="hot">Marked</Badge>}</div><button onClick={e => { e.preventDefault(); e.stopPropagation(); markInteresting('screenshots', s); }}>Mark screenshot</button></figcaption></figure>)}</div>
    {current && <div className="lightbox" role="dialog" aria-modal="true" aria-label="Screenshot preview" onMouseDown={close}>
      <div className="lightbox-panel" onMouseDown={e => e.stopPropagation()}>
        <div className="lightbox-head"><b>{hostFromUrl(current.url)}</b><span>{lightboxIndex + 1} / {rows.length}</span><button onClick={close}>Close</button></div>
        <button className="lightbox-nav prev" aria-label="Previous screenshot" onClick={() => move(-1)}>Prev</button>
        <img src={current.image_url} alt={`Screenshot of ${current.url}`}/>
        <button className="lightbox-nav next" aria-label="Next screenshot" onClick={() => move(1)}>Next</button>
        <div className="lightbox-foot"><span>{current.url}</span><button onClick={() => navigator.clipboard?.writeText(current.url)}>Copy URL</button><button onClick={() => markInteresting('screenshots', current)}>Mark</button></div>
      </div>
    </div>}
  </>;
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
    return <aside className="details empty"><h3>Details</h3><p>Select a host to inspect technologies, headers, tags, and quick actions.</p><div className="mini-chart"><b>Response Codes</b>{codes.map(([code, n]) => <div className="bar-row" key={code}><span>{code}</span><i style={{width: `${Math.min(100, n * 8)}%`}} /> <em>{n}</em></div>)}</div><div className="mini-chart"><b>Top Technologies</b>{techs.map(([tech, n]) => <div className="bar-row" key={tech}><span>{tech}</span><i style={{width: `${Math.min(100, n * 8)}%`}} /> <em>{n}</em></div>)}</div><div className="timeline"><b>Scan Timeline</b><p>Subdomains → Httpx → FFUF → Nuclei → Gowitness → Finished</p></div></aside>;
  }
  const value = row.url || row.source_url || row.matched_at || row.name || row.image_path;
  const cdn = compactTech(row.tech).find(t => /cloudfront|cloudflare|akamai|fastly/i.test(t)) || '—';
  const asn = /amazon|aws|cloudfront|s3/i.test((row.tech || []).join(' ')) ? 'Amazon' : /cloudflare/i.test((row.tech || []).join(' ')) ? 'Cloudflare' : '—';
  return <aside className="details"><button className="close" onClick={close}>Close</button><div className="details-host">{faviconFor(value)}<h3>{hostFromUrl(value)}</h3></div><p className="subtext">{value}</p><div className="detail-row"><span>Status</span>{row.status_code ? <Badge tone={statusClass(row.status_code)}>{row.status_code}</Badge> : '—'}</div><div className="detail-row"><span>Nuclei Finding</span>{row.template_id ? <><Badge tone={row.severity === 'critical' || row.severity === 'high' ? 'server' : 'warn'}>{row.severity}</Badge><Badge>{row.template_id}</Badge></> : '—'}</div><div className="detail-row"><span>Template Name</span>{row.template_name || '—'}</div><div className="detail-row"><span>Matcher / Type</span>{[row.matcher_name, row.type].filter(Boolean).join(' · ') || '—'}</div><div className="detail-row"><span>JS Finding</span>{row.finding_type ? <><Badge tone={row.severity === 'high' ? 'server' : row.severity === 'medium' ? 'warn' : 'muted'}>{row.severity}</Badge><Badge>{row.finding_type}</Badge></> : '—'}</div><div className="detail-row"><span>Indicator</span>{row.indicator || '—'}</div><div className="detail-row"><span>Location</span>{row.line ? `Line ${row.line}${row.column ? `, column ${row.column}` : ''}` : '—'}</div><div className="detail-row"><span>Page URL</span>{row.page_url || '—'}</div><div className="detail-row"><span>Parameter</span>{row.param ? <><Badge tone={row.suspicious ? 'warn' : 'muted'}>{row.param}</Badge>{row.method && <Badge>{row.method}</Badge>}</> : '—'}</div><div className="detail-row"><span>Param Reason</span>{row.reason || '—'}</div><div className="detail-row"><span>Sample Value</span>{row.sample_value || '—'}</div><div className="detail-row"><span>IP</span>{row.ip || '—'}</div><div className="detail-row"><span>Ports</span>{(row.ports || []).length ? (row.ports || []).join(', ') : '—'}</div><div className="detail-row"><span>ASN</span>{asn}</div><div className="detail-row"><span>CDN</span>{cdn}</div><div className="detail-row"><span>Title / Path</span>{row.title || row.path || row.base_url || row.matched_at || '—'}</div><div className="detail-row"><span>Confidence</span>{row.confidence ? <Badge tone={row.confidence === 'confirmed' ? 'ok' : row.confidence === 'possible' ? 'warn' : row.confidence === 'filtered' ? 'client' : 'muted'}>{row.confidence}</Badge> : '—'}</div><div className="detail-row"><span>Size / Words / Lines</span>{[row.size && `${row.size} B`, row.words && `${row.words} words`, row.lines && `${row.lines} lines`].filter(Boolean).join(' · ') || '—'}</div><div className="detail-row"><span>Filtered Reason</span>{row.filtered_reason || '—'}</div><div className="detail-row"><span>Fingerprints</span><TechBadges tech={row.fingerprints} max={8}/></div><div className="detail-row"><span>Technologies</span><TechBadges tech={row.tech} max={8}/></div><div className="detail-row"><span>Tags</span>{tagsFor(row).map(t => <Badge key={t}>{t}</Badge>)}</div>{row.description && <div className="detail-block"><span>Description</span><pre>{row.description}</pre></div>}{(row.extracted_results || []).length > 0 && <div className="detail-block"><span>Extracted Results</span><pre>{(row.extracted_results || []).join('\n')}</pre></div>}{(row.references || []).length > 0 && <div className="detail-block"><span>References</span><pre>{(row.references || []).join('\n')}</pre></div>}{row.evidence && <div className="detail-block"><span>Evidence</span><pre>{row.evidence}</pre></div>}{row.file_path && <div className="detail-block"><span>Downloaded bundle</span><pre>{row.file_path}</pre></div>}<div className="detail-block"><span>Response headers</span><pre>{JSON.stringify(row.response_headers || {}, null, 2)}</pre></div><div className="detail-block"><span>Headers sent</span><pre>{JSON.stringify(row.headers_sent || {}, null, 2)}</pre></div>{row.raw && <div className="detail-block"><span>Nuclei Raw</span><pre>{JSON.stringify(row.raw || {}, null, 2)}</pre></div>}<div className="detail-actions"><button onClick={() => window.open(value, '_blank')}>Open</button><button onClick={() => navigator.clipboard?.writeText(value)}>Copy URL</button><button>Screenshot</button><button>Whois</button><button>Run Nuclei</button><button>Crawl</button><button onClick={() => markInteresting(row.kind, row)}>Mark</button></div></aside>;
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

function LandingPage({domain, setDomain, run, targets, loadTarget, runDisabled, runError, alert, openSettings}) {
  const examples = ['example.com', 'app.example.com', 'https://target.com'];
  const needsOptions = Boolean(runError);
  return <div className="landing-page">
    <nav className="landing-nav"><b>Recon Radar</b><div className="landing-actions"><button className="secondary" onClick={openSettings}>Settings</button><button className="secondary" onClick={() => window.open('/logs', '_blank', 'noopener,noreferrer')}>View Logs</button></div></nav>
    <section className="landing-hero">
      <div className="landing-copy"><span className="eyebrow">Attack surface scanner</span><h1>Enter a target. Watch the surface resolve.</h1><p>Start with one domain and move into a focused scan workspace for subdomains, live hosts, content paths, vulnerabilities, screenshots, and raw output.</p></div>
      <form className="target-launcher" onSubmit={e => { e.preventDefault(); if (!runDisabled) run(); }}>
        <label>Target URL or domain</label>
        <div className="launcher-row"><input autoFocus value={domain} onChange={e => setDomain(e.target.value)} placeholder="example.com"/><button className="primary" type={needsOptions ? 'button' : 'submit'} disabled={!needsOptions && runDisabled} onClick={needsOptions ? openSettings : undefined}>{needsOptions ? 'Fix options' : 'Start scan'}</button></div>
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
  const [tail, setTail] = useState(localStorage.getItem('logs.tail') || '1000');
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
  function setTailNumber(value) { setTail(String(Math.min(2000, Math.max(0, Number(value) || 0)))); }
  function onScroll() { const el = scrollerRef.current; if (!el) return; const nearBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 48; if (!nearBottom) { setAutoScroll(false); setJump(true); } else setJump(false); }
  function reconnect() { window.location.reload(); }
  return <div className="logs-page"><div className="logs-toolbar"><div><h1>Live Container Logs</h1><p>Docker Compose infrastructure logs. Content is redacted server-side and rendered as plain text.</p></div><Badge tone={status === 'Connected' ? 'ok' : status === 'Reconnecting' ? 'warn' : 'server'}>{status}</Badge><button onClick={reconnect}>Reconnect</button></div>
    {error && <div className="inline-alert">{error}</div>}
    <div className="logs-toolbar sticky"><label>Container <select value={container} onChange={e => setContainer(e.target.value)}><option value="all">All containers</option>{containers.map(c => <option key={c.id} value={c.id}>{c.display_name} ({c.status})</option>)}</select></label><input className="wide" placeholder="Search/filter logs" value={query} onChange={e => setQuery(e.target.value)}/><label>Level <select value={level} onChange={e => setLevel(e.target.value)}>{['All','DEBUG','INFO','WARNING','ERROR','CRITICAL'].map(x => <option key={x}>{x}</option>)}</select></label><label>Tail <input type="number" min="0" max="2000" disabled={tail === 'all'} value={tail === 'all' ? 0 : tail} onChange={e => setTailNumber(e.target.value)}/></label><button onClick={() => setTail(tail === 'all' ? '1000' : 'all')}>{tail === 'all' ? 'Latest only' : 'Load all history'}</button><button onClick={() => setPaused(!paused)}>{paused ? `Resume${pending ? ` (${pending})` : ''}` : 'Pause'}</button><button onClick={() => setLines([])}>Clear</button><label><input type="checkbox" checked={autoScroll} onChange={e => setAutoScroll(e.target.checked)}/> Auto-scroll</label><button onClick={copyVisible}>Copy visible logs</button><button onClick={downloadVisible}>Download</button><span>{visible.length} visible / {lines.length} buffered</span></div>
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
  const [loadingTarget, setLoadingTarget] = useState(null);
  const [targetDrawerOpen, setTargetDrawerOpen] = useState(false);
  const [settingsDrawerOpen, setSettingsDrawerOpen] = useState(false);
  const targetLoadSequence = useRef(0);
  const [opts, setOpts] = useState(loadStoredScanOpts);
  useEffect(() => { localStorage.setItem('scan.options', JSON.stringify(opts)); }, [opts]);

  const refreshMeta = useCallback(async () => {
    const [targetRows, wordlistRows, appSettings, healthInfo] = await Promise.all([j(`${API}/targets`), j(`${API}/wordlists`), j(`${API}/settings`), j(`${API}/health`)]);
    setTargets(targetRows); setWordlists(wordlistRows); setSettings(appSettings); setHealth(healthInfo);
  }, []);
  const refreshResult = useCallback(async (targetId = active?.id) => {
    if (targetId) {
      const nextResult = await j(`${API}/targets/${targetId}/results`);
      setResult(nextResult);
      setScan(nextResult?.active_scan || null);
    }
  }, [active?.id]);
  const refresh = useCallback(async (targetId = active?.id) => {
    await refreshMeta();
    await refreshResult(targetId);
  }, [active?.id, refreshMeta, refreshResult]);
  useEffect(() => { refresh(); }, [refresh]);
  const scanForPolling = result ? result.active_scan : scan;
  const shouldPollScan = Boolean(scanForPolling?.id) && (!scanForPolling?.status || ['queued', 'running', 'stopping'].includes(scanForPolling.status));
  usePoll(scanForPolling?.id, () => refreshResult(active?.id), shouldPollScan);

  async function run() {
    setAlert('');
    try {
      const payload = {domain, ...opts, subdomain_wordlist_id: opts.subdomain_wordlist_id ? Number(opts.subdomain_wordlist_id) : null, dirb_wordlist_id: opts.dirb_wordlist_id ? Number(opts.dirb_wordlist_id) : null};
      const res = await j(`${API}/scans/run`, {method: 'POST', body: JSON.stringify(payload)});
      setScan({id: res.scan_id}); setActive({id: res.target_id, domain}); await refresh(res.target_id);
    } catch (err) {
      setAlert(err.message || String(err));
    }
  }
  async function loadTarget(t) {
    if (!t || loadingTarget) return;
    const sequence = ++targetLoadSequence.current;
    setAlert('');
    setLoadingTarget(t);
    // Let the loading screen paint before starting a potentially large response.
    await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
    try {
      const nextResult = await j(`${API}/targets/${t.id}/results`);
      if (sequence !== targetLoadSequence.current) return;
      setDomain(t.domain);
      setActive(t);
      setResult(nextResult);
      setScan(nextResult?.active_scan || null);
      setDetail(null);
      setSelectedIds(new Set());
      await new Promise(resolve => requestAnimationFrame(resolve));
    } catch (err) {
      if (sequence === targetLoadSequence.current) setAlert(`Could not load ${t.domain}: ${err.message || String(err)}`);
    } finally {
      if (sequence === targetLoadSequence.current) setLoadingTarget(null);
    }
  }
  async function deleteTarget(t) {
    const ok = window.confirm(`Delete target ${t.domain} and all scans/results/raw-output references for it? This cannot be undone.`);
    if (!ok) return;
    await j(`${API}/targets/${t.id}`, {method: 'DELETE'});
    if (active?.id === t.id) { setActive(null); setResult(null); setDetail(null); }
    await refresh();
  }
  async function clearSubdomainCache() {
    if (!active?.id) return;
    const name = active.domain || result?.target?.domain || 'this target';
    const ok = window.confirm(`Clear saved subdomains for ${name}? This keeps scans, live hosts, paths, parameters, screenshots, and logs.`);
    if (!ok) return;
    setAlert('');
    try {
      const res = await j(`${API}/targets/${active.id}/subdomains/cache`, {method: 'DELETE'});
      setAlert(`Cleared ${res.deleted?.subdomains || 0} cached subdomains.`);
      await refresh(active.id);
    } catch (err) {
      setAlert(err.message || String(err));
    }
  }
  async function stopScan() {
    const scanId = (result?.active_scan || scan)?.id;
    if (!scanId) return;
    setAlert('');
    try {
      const res = await j(`${API}/scans/${scanId}/stop`, {method: 'POST'});
      const stoppedScan = res.scan ? {...(result?.active_scan || scan || {}), ...res.scan} : {...(result?.active_scan || scan || {}), status: 'stopping'};
      setScan(stoppedScan);
      if (result) setResult({...result, active_scan: stoppedScan});
      await refreshResult(active?.id);
    } catch (err) {
      setAlert(err.message || String(err));
    }
  }
  async function runArjunOnSelectedParameters() {
    const parentScanId = result?.active_scan?.id || scan?.id;
    const urls = [...new Set(parameterRows.filter(r => selectedIds.has(r.id)).map(r => r.source_url || r.base_url).filter(Boolean))];
    if (!parentScanId || !urls.length) return;
    setAlert('');
    try {
      const payload = {
        subset_urls: urls,
        arjun_methods: opts.arjun_methods || 'GET',
        arjun_timeout: Number(opts.arjun_timeout) || 240,
        arjun_threads: Number(opts.arjun_threads) || 5,
        arjun_request_timeout: Number(opts.arjun_request_timeout) || 10,
        arjun_stable: Boolean(opts.arjun_stable),
      };
      const res = await j(`${API}/scans/${parentScanId}/arjun`, {method: 'POST', body: JSON.stringify(payload)});
      setScan({id: res.scan_id, status: 'queued', stage: 'queued:arjun'});
      setSelectedIds(new Set());
      await refresh(active?.id);
    } catch (err) {
      setAlert(err.message || String(err));
    }
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
  const nucleiRows = result?.nuclei_findings || [];
  const jsRows = result?.js_findings || [];
  const parameterRows = result?.parameters || [];
  const arjunRows = result?.arjun || [];
  const selectedParameterUrls = [...new Set(parameterRows.filter(r => selectedIds.has(r.id)).map(r => r.source_url || r.base_url).filter(Boolean))];
  const scanStatus = result?.active_scan || scan;
  const scanRunning = ['queued', 'running', 'stopping'].includes(scanStatus?.status);
  const defaultFfuf = health?.ffuf;
  const defaultAvailable = Boolean(defaultFfuf?.default_wordlist_available);
  const defaultName = defaultFfuf?.default_wordlist_name || 'common.txt';
  const defaultLabel = defaultName === 'common.txt' ? 'SecLists common.txt' : defaultName;
  const needsGenericFfuf = opts.run_ffuf && ['generic', 'combined'].includes(opts.ffuf_mode);
  const runError = needsGenericFfuf && !opts.dirb_wordlist_id && health && !defaultAvailable ? 'Generic FFUF is enabled, but no selected or default directory wordlist is available.' : '';
  const ffufWordlistHint = needsGenericFfuf && !opts.dirb_wordlist_id && defaultAvailable ? `${defaultLabel} will be used automatically for generic FFUF.` : '';
  const runDisabled = Boolean(runError) || scanRunning || !domain.trim();
  const settingsDrawer = <Drawer title="Scan settings" open={settingsDrawerOpen} onClose={() => setSettingsDrawerOpen(false)} wide>
    <SidebarGroup title="Wordlists"><label>Subdomain upload<input type="file" onChange={e => upload('subdomain', e.target.files[0])}/></label><label>Dirb upload<input type="file" onChange={e => upload('dirb', e.target.files[0])}/></label><select onChange={e => setOpts({...opts, subdomain_wordlist_id: e.target.value})}><option value="">Subdomain wordlist</option>{wordlists.filter(w => w.kind === 'subdomain').map(w => <option key={w.id} value={w.id}>{w.name}</option>)}</select><div className="option-stack"><span className="setting-label">Subdomain cache</span><label><input type="checkbox" checked={opts.use_cached_subdomains} onChange={e => setOpts({...opts, use_cached_subdomains: e.target.checked, fresh_subdomain_scan: e.target.checked ? false : opts.fresh_subdomain_scan})}/> Use saved subdomains for this target</label><label><input type="checkbox" checked={opts.refresh_passive_subdomains} onChange={e => setOpts({...opts, refresh_passive_subdomains: e.target.checked})}/> Refresh passive sources now</label><label><input type="checkbox" checked={opts.fresh_subdomain_scan} onChange={e => setOpts({...opts, fresh_subdomain_scan: e.target.checked, use_cached_subdomains: e.target.checked ? false : opts.use_cached_subdomains})}/> Fresh scan only, ignore saved subdomains</label><p className="hint">Default uses cache and refreshes Subfinder. Turn off refresh for cached-only scans.</p>{active?.id && <button className="danger small" type="button" onClick={clearSubdomainCache}>Clear subdomain cache for this target</button>}</div><div className="option-stack"><span className="setting-label">Passive discovery</span><label><input type="checkbox" checked={opts.subfinder_recursive} onChange={e => setOpts({...opts, subfinder_recursive: e.target.checked})}/> Use Subfinder recursive mode</label><label><input type="checkbox" checked={opts.use_crtsh} onChange={e => setOpts({...opts, use_crtsh: e.target.checked})}/> Use crt.sh certificate transparency</label><label><input type="checkbox" checked={opts.run_amass} onChange={e => setOpts({...opts, run_amass: e.target.checked})}/> Run Amass passive enrichment</label><input placeholder="amass timeout seconds" value={opts.amass_timeout} onChange={e => setOpts({...opts, amass_timeout: Number(e.target.value) || 600})}/><p className="hint">Subfinder recursive and crt.sh are off by default. Default command matches: subfinder -d target -silent -all.</p></div><div className="option-stack"><span className="setting-label">DNS brute force</span><label><input type="checkbox" checked={opts.use_subdomains_top1million_110000} onChange={e => setOpts({...opts, use_subdomains_top1million_110000: e.target.checked})}/> Use subdomains-top1million-110000.txt</label><label><input type="checkbox" checked={opts.use_bug_bounty_subdomains_trickest} onChange={e => setOpts({...opts, use_bug_bounty_subdomains_trickest: e.target.checked})}/> Use bug-bounty-program-subdomains-trickest-inventory.txt</label><p className="hint">Large DNS brute-force lists are off by default and results are saved in 100-row batches.</p></div><select value={opts.dirb_wordlist_id || ''} onChange={e => setOpts({...opts, dirb_wordlist_id: e.target.value})}><option value="">Default - {defaultLabel}</option>{wordlists.filter(w => w.kind === 'dirb').map(w => <option key={w.id} value={w.id}>{w.name}</option>)}</select>{ffufWordlistHint && <p className="hint">{ffufWordlistHint}</p>}{!defaultAvailable && opts.run_ffuf && !opts.dirb_wordlist_id && health && <p className="inline-alert">Default FFUF wordlist unavailable. Upload/select a dirb wordlist.</p>}</SidebarGroup>
    <SidebarGroup title="Request Settings">{settings && <><input value={settings.user_agent || ''} onChange={e => setSettings({...settings, user_agent: e.target.value})} placeholder="User-Agent"/><input value={settings.proxy || ''} onChange={e => setSettings({...settings, proxy: e.target.value})} placeholder="Proxy"/><textarea placeholder="Header: value per line" value={settings.headerLines ?? Object.entries(settings.headers || {}).map(([k, v]) => `${k}: ${v}`).join('\n')} onChange={e => setSettings({...settings, headerLines: e.target.value})}/><button onClick={saveSettings}>Save settings</button></>}</SidebarGroup>
    <SidebarGroup title="Port & Fingerprint"><label><input type="checkbox" checked={opts.run_naabu} onChange={e => setOpts({...opts, run_naabu: e.target.checked})}/> Run Naabu web-port discovery</label><input placeholder="naabu ports" value={opts.naabu_ports} onChange={e => setOpts({...opts, naabu_ports: e.target.value})}/><div className="option-stack always-on"><span className="setting-label">Wappalyzer fingerprinting</span><Badge tone="ok">Always on after httpx</Badge><select value={opts.wappalyzer_scan_type} onChange={e => setOpts({...opts, wappalyzer_scan_type: e.target.value})}><option value="balanced">Balanced</option><option value="fast">Fast</option><option value="full">Full browser mode</option></select><input placeholder="wappalyzer workers" value={opts.wappalyzer_workers} onChange={e => setOpts({...opts, wappalyzer_workers: Number(e.target.value) || 1})}/><p className="hint">Mandatory stage: Wappalyzer runs after httpx on all live hosts before tech-specific FFUF.</p></div></SidebarGroup>
    <SidebarGroup title="FFUF Options"><label><input type="checkbox" checked={opts.run_ffuf} onChange={e => setOpts({...opts, run_ffuf: e.target.checked})}/> Run directory discovery</label><select value={opts.ffuf_mode} onChange={e => setOpts({...opts, ffuf_mode: e.target.value})}><option value="tech">Tech-specific only</option><option value="combined">Tech-specific + generic</option><option value="generic">Generic only</option></select>{runError && <p className="inline-alert">{runError}</p>}<input placeholder="extensions php,txt" onChange={e => setOpts({...opts, extensions: e.target.value})}/><input placeholder="match codes" value={opts.ffuf_match_codes} onChange={e => setOpts({...opts, ffuf_match_codes: e.target.value})}/><input placeholder="host timeout seconds" value={opts.ffuf_host_timeout} onChange={e => setOpts({...opts, ffuf_host_timeout: e.target.value})}/><label><input type="checkbox" checked={opts.ffuf_auto_calibration} onChange={e => setOpts({...opts, ffuf_auto_calibration: e.target.checked})}/> Auto calibration (-ac)</label><label><input type="checkbox" checked={opts.ffuf_recursive} onChange={e => setOpts({...opts, ffuf_recursive: e.target.checked})}/> Recursive</label><p className="hint">Tech-specific mode uses small focused wordlists based on fingerprints and response headers.</p></SidebarGroup>
    <SidebarGroup title="Nuclei"><div className="option-stack"><span className="setting-label">Template scan</span><label><input type="checkbox" checked={opts.run_nuclei} onChange={e => setOpts({...opts, run_nuclei: e.target.checked})}/> Run Nuclei</label><select value={opts.nuclei_profile} onChange={e => setOpts({...opts, nuclei_profile: e.target.value})}><option value="light">Light and fast</option><option value="balanced">Balanced</option><option value="full">Full selected severities</option></select><input placeholder="severity high,critical" value={opts.nuclei_severity} onChange={e => setOpts({...opts, nuclei_severity: e.target.value || 'high,critical'})}/><input placeholder="include tags cves,exposure (optional)" value={opts.nuclei_tags} onChange={e => setOpts({...opts, nuclei_tags: e.target.value})}/><input placeholder="exclude tags dos,fuzz,intrusive" value={opts.nuclei_exclude_tags} onChange={e => setOpts({...opts, nuclei_exclude_tags: e.target.value})}/><input placeholder="specific templates or ids, comma-separated" value={opts.nuclei_templates} onChange={e => setOpts({...opts, nuclei_templates: e.target.value})}/><input placeholder="concurrency" value={opts.nuclei_concurrency} onChange={e => setOpts({...opts, nuclei_concurrency: Number(e.target.value) || 10})}/><input placeholder="rate limit req/s" value={opts.nuclei_rate_limit} onChange={e => setOpts({...opts, nuclei_rate_limit: Number(e.target.value) || 25})}/><input placeholder="request timeout seconds" value={opts.nuclei_timeout} onChange={e => setOpts({...opts, nuclei_timeout: Number(e.target.value) || 4})}/><input placeholder="retries" value={opts.nuclei_retries} onChange={e => setOpts({...opts, nuclei_retries: Number(e.target.value) || 0})}/><input placeholder="stage timeout seconds" value={opts.nuclei_stage_timeout} onChange={e => setOpts({...opts, nuclei_stage_timeout: Number(e.target.value) || 600})}/><input placeholder="max URLs" value={opts.nuclei_max_urls} onChange={e => setOpts({...opts, nuclei_max_urls: Number(e.target.value) || 100})}/><p className="hint">Light mode prioritizes high-signal templates and excludes slow or intrusive categories.</p></div></SidebarGroup>
    <SidebarGroup title="JS Intel"><div className="option-stack always-on"><span className="setting-label">JavaScript + TruffleHog</span><Badge tone="ok">Always on</Badge><input placeholder="max live hosts" value={opts.js_intel_max_hosts} onChange={e => setOpts({...opts, js_intel_max_hosts: Number(e.target.value) || 80})}/><input placeholder="max scripts per host" value={opts.js_intel_max_scripts_per_host} onChange={e => setOpts({...opts, js_intel_max_scripts_per_host: Number(e.target.value) || 25})}/><input placeholder="max bytes per file" value={opts.js_intel_max_bytes} onChange={e => setOpts({...opts, js_intel_max_bytes: Number(e.target.value) || 2000000})}/><input placeholder="stage timeout seconds" value={opts.js_intel_timeout} onChange={e => setOpts({...opts, js_intel_timeout: Number(e.target.value) || 180})}/><input placeholder="TruffleHog results verified,unknown,unverified" value={opts.trufflehog_results} onChange={e => setOpts({...opts, trufflehog_results: e.target.value || 'verified,unknown,unverified'})}/><input placeholder="TruffleHog concurrency" value={opts.trufflehog_concurrency} onChange={e => setOpts({...opts, trufflehog_concurrency: Number(e.target.value) || 4})}/><p className="hint">Always downloads/analyzes JS bundles, then runs TruffleHog filesystem secret scanning on those bundles.</p></div></SidebarGroup>
    <SidebarGroup title="Parameter Discovery"><label><input type="checkbox" checked={opts.run_parameters} onChange={e => setOpts({...opts, run_parameters: e.target.checked})}/> Run gau + Katana parameter discovery</label><input placeholder="katana depth" value={opts.katana_depth} onChange={e => setOpts({...opts, katana_depth: Number(e.target.value) || 2})}/><input placeholder="katana crawl duration (2m)" value={opts.katana_crawl_duration} onChange={e => setOpts({...opts, katana_crawl_duration: e.target.value || '2m'})}/><input placeholder="parameter timeout seconds" value={opts.parameter_timeout} onChange={e => setOpts({...opts, parameter_timeout: Number(e.target.value) || 240})}/><label><input type="checkbox" checked={opts.run_katana_headless} onChange={e => setOpts({...opts, run_katana_headless: e.target.checked})}/> Katana headless crawl</label><p className="hint">Extracts GET/POST parameters from gau and bounded Katana crawling only. Arjun runs as a separate stage.</p></SidebarGroup>
    <SidebarGroup title="Arjun Options"><input placeholder="methods GET or GET,POST" value={opts.arjun_methods} onChange={e => setOpts({...opts, arjun_methods: e.target.value || 'GET'})}/><input placeholder="arjun total timeout seconds" value={opts.arjun_timeout} onChange={e => setOpts({...opts, arjun_timeout: Number(e.target.value) || 240})}/><input placeholder="arjun threads" value={opts.arjun_threads} onChange={e => setOpts({...opts, arjun_threads: Number(e.target.value) || 5})}/><input placeholder="arjun request timeout seconds" value={opts.arjun_request_timeout} onChange={e => setOpts({...opts, arjun_request_timeout: Number(e.target.value) || 10})}/><label><input type="checkbox" checked={opts.arjun_stable} onChange={e => setOpts({...opts, arjun_stable: e.target.checked})}/> Prefer stability over speed</label><p className="hint">Arjun is manual-only. Select URLs on the Arjun page and run it when you want hidden parameter probing.</p></SidebarGroup>
  </Drawer>;

  if (!active && !result && !scan) {
    return <><LandingPage domain={domain} setDomain={setDomain} run={run} targets={targets} loadTarget={loadTarget} runDisabled={runDisabled} runError={runError} alert={alert} openSettings={() => setSettingsDrawerOpen(true)}/>{settingsDrawer}<TargetLoadingScreen target={loadingTarget}/></>;
  }

  return <><div className="app-shell">
    <Header domain={domain} setDomain={setDomain} run={run} stopScan={stopScan} result={result} targets={targets} loadTarget={loadTarget} runDisabled={runDisabled} runError={runError} openTargets={() => setTargetDrawerOpen(true)} openSettings={() => setSettingsDrawerOpen(true)}/>{alert && <div className="alert">{alert}</div>}
    <main className="layout">
    <section className="workspace"><SummaryCards result={result}/><ProgressPanel scan={scanStatus} result={result}/><div className="tabs">{TABS.map(t => <button className={tab === t ? 'sel' : ''} onClick={() => setTab(t)} key={t}>{t} <span>{t === 'Subdomains' ? subdomainRows.length : t === 'Live Hosts' ? httpRows.length : t === 'Content Paths' ? dirRows.length : t === 'Vulnerabilities' ? nucleiRows.length : t === 'JS Intel' ? jsRows.length : t === 'Parameters' ? parameterRows.length : t === 'Arjun' ? arjunRows.length : t === 'Screenshots' ? (result?.screenshots || []).length : (result?.raw || []).length}</span></button>)}<div className="export-buttons"><button onClick={() => active && window.open(`${API}/targets/${active.id}/export?format=json`, '_blank')}>Export JSON</button><button onClick={() => active && window.open(`${API}/targets/${active.id}/export?format=csv`, '_blank')}>Export CSV</button></div></div>
      {tab === 'Subdomains' && <AssetTable rows={subdomainRows} kind="subdomains" selectRow={setDetail} selectedIds={selectedIds} toggleSelected={toggleSelected} markInteresting={markInteresting}/>}
      {tab === 'Live Hosts' && <><h3>200 OK</h3><AssetTable rows={http200} kind="http" selectRow={setDetail} selectedIds={selectedIds} toggleSelected={toggleSelected} markInteresting={markInteresting}/><h3>Other Status Codes</h3><AssetTable rows={httpOther} kind="http" selectRow={setDetail} selectedIds={selectedIds} toggleSelected={toggleSelected} markInteresting={markInteresting}/></>}
      {tab === 'Content Paths' && <AssetTable rows={dirRows} kind="dirs" selectRow={setDetail} selectedIds={selectedIds} toggleSelected={toggleSelected} markInteresting={markInteresting}/>}
      {tab === 'Vulnerabilities' && <AssetTable rows={nucleiRows} kind="nuclei_findings" selectRow={setDetail} selectedIds={selectedIds} toggleSelected={toggleSelected} markInteresting={markInteresting}/>}
      {tab === 'JS Intel' && <AssetTable rows={jsRows} kind="js_findings" selectRow={setDetail} selectedIds={selectedIds} toggleSelected={toggleSelected} markInteresting={markInteresting}/>}
      {tab === 'Parameters' && <AssetTable rows={parameterRows} kind="parameters" selectRow={setDetail} selectedIds={selectedIds} toggleSelected={toggleSelected} markInteresting={markInteresting}/>}
      {tab === 'Arjun' && <><div className="bulkbar action-strip"><span>{selectedParameterUrls.length} selected URL{selectedParameterUrls.length === 1 ? '' : 's'} ready for Arjun</span><button className="primary" disabled={!selectedParameterUrls.length || scanRunning} onClick={runArjunOnSelectedParameters}>Run Arjun on selected URLs</button><span className="muted">Select candidate URLs below; results appear in the Arjun Results table.</span></div><h3>Candidate URLs from Parameter Discovery</h3><AssetTable rows={parameterRows} kind="parameters" selectRow={setDetail} selectedIds={selectedIds} toggleSelected={toggleSelected} markInteresting={markInteresting}/><h3>Arjun Results</h3><AssetTable rows={arjunRows} kind="parameters" selectRow={setDetail} selectedIds={selectedIds} toggleSelected={toggleSelected} markInteresting={markInteresting}/></>}
      {tab === 'Screenshots' && <ScreenshotGallery rows={result?.screenshots || []} selectRow={setDetail} markInteresting={markInteresting}/>}
      {tab === 'Raw Logs' && <RawConsole rows={result?.raw || []}/>}
    </section></main>
  </div>
  <Drawer title="Targets & history" open={targetDrawerOpen} onClose={() => setTargetDrawerOpen(false)}>
    <SidebarGroup title="Recent Targets">{targets.map(t => <div className="target-row" key={t.id}><button className="target" onClick={() => { setTargetDrawerOpen(false); loadTarget(t); }}>{t.domain}<span>{t.scan_count} scans</span></button><button className="danger small" title={`Delete ${t.domain}`} onClick={() => deleteTarget(t)}>Delete</button></div>)}</SidebarGroup>
    <SidebarGroup title="Scan History">{(result?.scans || []).map(s => <button className="target scan-history-item" key={s.id} onClick={() => { setTargetDrawerOpen(false); j(`${API}/targets/${active.id}/results?scan_id=${s.id}`).then(setResult); }}><b>Scan #{s.id}</b><span>{ago(s.created_at)} · {s.status}</span></button>)}</SidebarGroup>
    <SidebarGroup title="Marked Targets"><p className="muted">Marked rows remain highlighted in the result tables.</p></SidebarGroup>
  </Drawer>
  {settingsDrawer}
  <Drawer title="Host details" open={Boolean(detail)} onClose={() => setDetail(null)} wide>
    <DetailsPanel row={detail} result={result} close={() => setDetail(null)} markInteresting={markInteresting}/>
  </Drawer>
  <TargetLoadingScreen target={loadingTarget}/></>;
}

createRoot(document.getElementById('root')).render(window.location.pathname === '/logs' ? <LogsPage/> : <App/>);
