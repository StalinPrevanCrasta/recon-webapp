import React, {useCallback, useEffect, useMemo, useRef, useState} from 'react';
import {createRoot} from 'react-dom/client';
import './style.css';

const API = '/api';
const TABS = ['Subdomains', 'Live Hosts', 'Content Paths', 'Vulnerabilities', 'JS Intel', 'Parameters', 'Screenshots', 'Raw Logs'];
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
  max_ffuf_hosts: null,
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
  run_nuclei: false,
  nuclei_profile: 'light',
  nuclei_severity: 'high,critical',
  nuclei_tags: 'exposure,takeover',
  nuclei_exclude_tags: 'dos,fuzz,intrusive,brute-force,bruteforce,slow',
  nuclei_types: 'http',
  nuclei_templates: '',
  nuclei_concurrency: 10,
  nuclei_rate_limit: 25,
  nuclei_timeout: 4,
  nuclei_retries: 0,
  nuclei_stage_timeout: 300,
  nuclei_max_urls: 25,
  nuclei_no_interactsh: true,
  nuclei_include_content_paths: false,
  run_parameters: true,
  katana_depth: 2,
  run_katana_headless: false,
  parameter_timeout: 240,
  katana_crawl_duration: '2m',
  max_katana_urls: 80,
  max_katana_output_mb: 250,
  run_arjun: false,
  arjun_methods: 'GET',
  arjun_timeout: 240,
  arjun_threads: 5,
  arjun_request_timeout: 10,
  arjun_stable: true,
  run_screenshots: true,
  max_screenshot_urls: null,
  stale_scan_minutes: 30,
  use_subdomains_top1million_110000: false,
  use_bug_bounty_subdomains_trickest: false,
};

function loadStoredScanOpts() {
  try {
    const stored = JSON.parse(localStorage.getItem('scan.options') || '{}');
    if (localStorage.getItem('nuclei.manualDefault.v1') !== 'true') {
      stored.run_nuclei = false;
      localStorage.setItem('nuclei.manualDefault.v1', 'true');
    }
    return {...DEFAULT_SCAN_OPTS, ...stored};
  } catch {
    return DEFAULT_SCAN_OPTS;
  }
}

function playgroundUrlForRow(row = {}) {
  const value = row.url || row.source_url || row.page_url || row.matched_at || row.base_url || row.name || '';
  if (!value || /^https?:\/\//i.test(value)) return value;
  return value.includes('.') ? `https://${value}` : value;
}

function openUrl(value = '') {
  const url = String(value).trim();
  if (!url || /^https?:\/\//i.test(url)) return url;
  return url.includes('.') ? `https://${url}` : url;
}

function playgroundRequestForRow(row = {}) {
  return {
    method: row.method || 'GET',
    url: playgroundUrlForRow(row),
    headers: row.headers_sent || {},
    body: '',
    source: row.kind || row.finding_type || row.source || row.template_id || '',
    label: row.path || row.param || row.indicator || row.title || row.template_name || '',
  };
}

function sendRowsToPlayground(rows = []) {
  const requests = rows.map(playgroundRequestForRow).filter(item => item.url);
  if (!requests.length) return;
  localStorage.setItem('playground.seed', JSON.stringify(requests[0]));
  localStorage.setItem('playground.queue', JSON.stringify(requests));
  window.open('/playground', '_blank', 'noopener,noreferrer');
}

function sendToPlayground(row = {}) {
  sendRowsToPlayground([row]);
}

function nucleiUrlForRow(row = {}) {
  return row.url || row.source_url || row.page_url || row.base_url || row.matched_at || '';
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

function isApiRow(row = {}) {
  if ((row.tags || []).includes('api')) return true;
  const value = String(row.url || row.source_url || row.matched_at || row.name || '');
  let path = value;
  try { path = new URL(value).pathname; } catch {}
  if (/\.(?:pdf|css|js|map|png|jpe?g|gif|svg|woff2?|ttf|docx?|xlsx?|pptx?|zip)(?:$|[?#])/i.test(path)) return false;
  if (/\/(?:asset|assets|blog|careers|events|investors|legal|news|partner|press|privacy|solutions|support)(?:\/|$)/i.test(path) && !/\/(?:api|graphql|rest|openapi|swagger|wp-json)(?:\/|$)/i.test(path)) return false;
  return /\/(?:api|graphql|rest|openapi|swagger|wp-json|v\d+)(?:\/|$)/i.test(path);
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
  if (row.severity === 'high' && row.probable_vulnerability) tags.push('High Signal');
  if (row.severity === 'high' && row.classification === 'interesting_lead') tags.push('Review');
  if (row.severity === 'medium') tags.push('Review');
  if (row.classification === 'interesting_lead') tags.push('Lead');
  if (row.probable_vulnerability) tags.push('Probable');
  if ((row.observation_count || 1) > 1) tags.push(`${row.observation_count}× grouped`);
  if ((row.tags || []).includes('source-sink')) tags.push('Source → Sink');
  if ((row.tags || []).includes('secret')) tags.push('Secret');
  if (/admin|manage|console|dashboard/.test(haystack)) tags.push('Admin');
  if (/login|signin|sso|auth/.test(haystack)) tags.push('Login');
  if (isApiRow(row)) tags.push('API');
  if (/jenkins|kibana|grafana/.test(haystack)) tags.push('Dashboard');
  return tags;
}

function jsFinder(row) {
  if (!row?.finding_type) return '';
  return row.finder || ((row.tags || []).includes('trufflehog') || String(row.finding_type).startsWith('trufflehog') ? 'TruffleHog' : 'Custom JS analyzer');
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
  const jsHigh = jsFindings.filter(j => j.severity === 'high' && j.probable_vulnerability).length;
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
  const summary = result?.summary || {};
  const rawCounts = summary.raw_counts || {};
  return <>
    <div className="cards compact-cards">
      <div className="card"><span className="card-label">DNS</span><b>{subdomains}</b><span>Subdomains</span><small>{newSubdomains} new · {cachedSubdomains} cached</small></div>
      <div className="card"><span className="card-label">HOSTS</span><b>{summary.unique_hosts ?? live}</b><span>Unique hosts</span><small>{rawCounts.http ?? http.length} raw HTTP observations</small></div>
      <div className="card"><span className="card-label">VISUAL</span><b>{screenshots}</b><span>Screenshots</span></div>
      <div className="card"><span className="card-label">ENDPOINTS</span><b>{summary.unique_endpoints ?? dirs.length}</b><span>Unique endpoints</span><small>{rawCounts.dirs ?? dirs.length} raw paths · {confirmedDirs} confirmed</small></div>
      <div className="card"><span className="card-label">PARAMS</span><b>{summary.unique_parameters ?? (result?.parameters || []).length}</b><span>Unique parameters</span><small>{rawCounts.parameters ?? (result?.parameters || []).length} raw observations</small></div>
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
  const highJsFindings = jsFindings.filter(j => j.severity === 'high' && j.probable_vulnerability).length;
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
    ['parameters', 'Parameters', `${parameters.length} params · ${stageInfo.parameters?.suspicious || 0} suspicious${stageInfo.parameters?.katana_input_urls ? ` · ${stageInfo.parameters.katana_input_urls} Katana URLs` : ''}${stageInfo.parameters?.raw_compacted ? ' · raw compacted' : ''}`],
    ['screenshots', 'Gowitness', `${stageInfo.screenshots?.input_urls || '—'} sent · ${stageInfo.screenshots?.saved ?? screenshotCount} saved${stageInfo.screenshots?.failed != null ? ` · ${stageInfo.screenshots.failed} failed` : ''}`],
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
  const counts = `${result?.subdomains?.length || 0} subdomains | ${result?.summary?.unique_hosts ?? (result?.http || []).length} unique hosts | ${result?.summary?.unique_endpoints ?? (result?.dirs || []).length} endpoints | ${result?.summary?.unique_parameters ?? (result?.parameters || []).length} params | ${result?.nuclei_findings?.length || 0} vulns`;
  const activeScan = ['queued', 'running', 'stopping'].includes(scan?.status);
  return <header>
    <div className="brand"><h1>{target}</h1><div className="header-meta"><Badge tone={scan?.status === 'complete' ? 'ok' : 'redirect'}>{scan?.status || 'ready'}</Badge><span>{counts}</span><span>Started: {ago(scan?.started_at || scan?.created_at)}</span></div></div>
    <div className="runbox"><select onChange={e => { const t = targets.find(x => String(x.id) === e.target.value); if (t) loadTarget(t); }}><option>Recent targets</option>{targets.slice(0, 12).map(t => <option key={t.id} value={t.id}>{t.domain}</option>)}</select><input className="target-input" value={domain} onChange={e => setDomain(e.target.value)} placeholder="example.com"/><button className="secondary" onClick={openTargets}>Targets</button><button className="secondary" onClick={openSettings}>Settings</button><button className="secondary" onClick={() => window.open('/playground', '_blank', 'noopener,noreferrer')}>Playground</button><button className="secondary" onClick={() => window.open('/security-lab', '_blank', 'noopener,noreferrer')}>Security Lab</button><button className="secondary" title="Open live container logs" onClick={() => window.open('/logs', '_blank', 'noopener,noreferrer')}>View Logs</button>{activeScan && <button className="danger" disabled={scan?.status === 'stopping'} onClick={stopScan}>{scan?.status === 'stopping' ? 'Stopping…' : 'Stop scan'}</button>}<button className="primary" disabled={runDisabled} title={runError || ''} onClick={run}>{runDisabled ? 'Fix options' : 'Run scan'}</button></div>{runError && <div className="inline-alert">{runError}</div>}
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
      (!filters.chips.includes('APIs') || isApiRow(row)) &&
      (!filters.chips.includes('Login') || /login|signin|sso|auth/i.test(blob)) &&
      (!filters.chips.includes('Admin') || /admin|manage|console|dashboard/i.test(blob)) &&
      (!filters.chips.includes('GraphQL') || /graphql/i.test(blob)) &&
      (!filters.chips.includes('Swagger') || /swagger|openapi/i.test(blob)) &&
      (!filters.chips.includes('Takeover') || /github|heroku|netlify|s3|azure|cloudfront/i.test(blob));
  });
}

function AssetTable({rows, kind, selectRow, selectedIds, toggleSelected, markInteresting, runNucleiOnRows}) {
  const [filters, setFilters] = useState({q: '', host: '', status: '', title: '', tech: '', ip: '', source: '', tags: '', confidence: '', chips: []});
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);
  const [expanded, setExpanded] = useState(() => new Set());
  const filtered = useMemo(() => applyFilters(rows, filters), [rows, filters]);
  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const safePage = Math.min(page, totalPages);
  const visible = filtered.slice((safePage - 1) * pageSize, safePage * pageSize);
  useEffect(() => { setPage(1); }, [filters, kind]);
  const copy = value => navigator.clipboard?.writeText(value).catch(() => {});
  const selectedRows = filtered.filter(r => selectedIds.has(r.id));
  return <>
    <Filters filters={filters} setFilters={setFilters}/>
    <div className="bulkbar"><label><input type="checkbox" onChange={e => visible.forEach(r => toggleSelected(r.id, e.target.checked))}/> Select page</label><span>{selectedRows.length} selected here</span><button onClick={() => copy(selectedRows.map(r => r.url || r.source_url || r.name || r.matched_at).filter(Boolean).join('\n'))}>Copy selected</button><button className="primary subtle" disabled={!selectedRows.length} onClick={() => sendRowsToPlayground(selectedRows)}>Send selected to Playground</button><div className="pager"><button disabled={safePage <= 1} onClick={() => setPage(safePage - 1)}>Prev</button><span>Page {safePage} / {totalPages} · {filtered.length} results</span><button disabled={safePage >= totalPages} onClick={() => setPage(safePage + 1)}>Next</button><select value={pageSize} onChange={e => { setPageSize(Number(e.target.value)); setPage(1); }}><option value="50">50/page</option><option value="100">100/page</option><option value="250">250/page</option></select></div></div>
    <div className="table-wrap"><table className={`asset-table ${kind}`}><colgroup><col className="col-select"/><col className="col-host"/><col className="col-status"/><col className="col-title"/><col className="col-ip"/><col className="col-tech"/><col className="col-source"/><col className="col-tags"/><col className="col-confidence"/><col className="col-actions"/></colgroup><thead><tr><th></th><th>Host</th><th>Status</th><th>Title</th><th>IP</th><th>Tech</th><th>Source</th><th>Tags</th><th>Confidence</th><th>Actions</th></tr></thead><tbody>{visible.map(row => {
      const value = row.url || row.source_url || row.matched_at || row.name;
      const tags = tagsFor(row);
      const grouped = (row.observation_count || 1) > 1;
      const isExpanded = expanded.has(row.id);
      return <React.Fragment key={`${kind}-${row.id}`}><tr onClick={() => selectRow({...row, kind})} className={row.is_new ? 'new' : ''}>
        <td onClick={e => e.stopPropagation()}><input type="checkbox" checked={selectedIds.has(row.id)} onChange={e => toggleSelected(row.id, e.target.checked)}/></td>
        <td title={value}><div className="host-cell">{faviconFor(value)}<div><b>{hostFromUrl(value)}</b><div className="subtext">{value}</div>{grouped && <button className="equivalent-toggle" onClick={e => { e.stopPropagation(); setExpanded(current => { const next = new Set(current); if (next.has(row.id)) next.delete(row.id); else next.add(row.id); return next; }); }}>{isExpanded ? 'Hide' : 'Show'} {row.observation_count} equivalent</button>}</div></div></td>
        <td>{row.status_code ? <Badge tone={statusClass(row.status_code)}>{row.status_code}</Badge> : <span className="muted">—</span>}</td>
        <td title={[row.title || row.template_name || row.path || row.param || row.indicator || row.template_id || '', row.reason || row.evidence || row.description || ''].filter(Boolean).join('\n')}><div className="cell-main">{row.title || row.template_name || row.path || row.param || row.indicator || row.template_id || <span className="muted">—</span>}</div><div className="subtext">{row.reason || row.evidence || row.description || ''}</div></td>
        <td>{row.ip || (row.line ? `Line ${row.line}` : <span className="muted">—</span>)}<div className="subtext">{(row.ports || []).length ? `Ports ${(row.ports || []).join(', ')}` : row.column ? `Column ${row.column}` : ''}</div></td>
        <td>{row.finding_type ? <TechBadges tech={[jsFinder(row), row.finding_type, ...(row.tags || [])]} max={8} /> : row.template_id ? <TechBadges tech={[row.type || 'nuclei', ...(row.tags || [])]} /> : <TechBadges tech={[...(row.fingerprints || []), ...(row.tech || [])]} />}</td>
        <td title={jsFinder(row) || (row.sources || []).join(', ') || row.source || row.finding_type || row.template_id || row.base_url || ''}><div className="cell-main">{jsFinder(row) || (row.sources || []).join(', ') || row.source || row.finding_type || row.template_id || row.base_url || <span className="muted">—</span>}</div>{row.finding_type && <div className="subtext">{row.finding_type}</div>}</td>
        <td>{tags.length ? tags.map(t => <Badge key={t} tone={t === 'Marked' ? 'hot' : t === 'Filtered' ? 'client' : t === 'Possible' ? 'warn' : t === 'Confirmed' ? 'ok' : 'muted'}>{t}</Badge>) : <span className="muted">—</span>}</td>
        <td>{row.severity ? <Badge tone={row.severity === 'critical' || row.severity === 'high' ? 'server' : row.severity === 'medium' ? 'warn' : 'muted'}>{row.severity}</Badge> : row.confidence ? <Badge tone={row.confidence === 'confirmed' ? 'ok' : row.confidence === 'possible' ? 'warn' : row.confidence === 'filtered' ? 'client' : 'muted'}>{row.confidence}</Badge> : <span className="muted">—</span>}<div className="score-row"><Badge tone={(row.noise_score || 0) >= 50 ? 'client' : 'muted'}>Noise {row.noise_score || 0}</Badge><Badge tone={(row.novelty_score || 0) >= 50 ? 'ok' : 'muted'}>Novel {row.novelty_score || 0}</Badge></div><div className="subtext">{row.confidence && row.severity ? row.confidence : ''}{row.size ? `${row.size} B` : ''}{row.words ? ` · ${row.words}w` : ''}</div></td>
        <td className="actions" onClick={e => e.stopPropagation()}><button onClick={() => window.open(openUrl(value), '_blank', 'noopener,noreferrer')}>Open</button><button onClick={() => copy(value)}>Copy</button><button title="Send to Playground" onClick={() => sendToPlayground({...row, kind})}>Playground</button><button onClick={() => markInteresting(kind, row)}>Mark</button><button title="Screenshot">Shot</button><button title="Run Nuclei on this row" disabled={!runNucleiOnRows || !nucleiUrlForRow(row)} onClick={() => runNucleiOnRows([row])}>Nuclei</button></td>
      </tr>{isExpanded && <tr className="equivalent-row"><td></td><td colSpan="9"><b>Equivalent observations</b><div className="equivalent-list">{(row.variants || []).map((variant, index) => <span key={`${variant.url || variant.source_url || index}-${index}`}>{variant.url || variant.source_url || JSON.stringify(variant)}</span>)}</div>{row.observation_count > (row.variants || []).length && <small>Showing {(row.variants || []).length} of {row.observation_count} observations.</small>}</td></tr>}</React.Fragment>;
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
  return <aside className="details"><div className="details-host">{faviconFor(value)}<h3>{hostFromUrl(value)}</h3></div><p className="subtext">{value}</p><div className="detail-row"><span>Status</span>{row.status_code ? <Badge tone={statusClass(row.status_code)}>{row.status_code}</Badge> : '—'}</div><div className="detail-row"><span>Nuclei Finding</span>{row.template_id ? <><Badge tone={row.severity === 'critical' || row.severity === 'high' ? 'server' : 'warn'}>{row.severity}</Badge><Badge>{row.template_id}</Badge></> : '—'}</div><div className="detail-row"><span>Template Name</span>{row.template_name || '—'}</div><div className="detail-row"><span>Matcher / Type</span>{[row.matcher_name, row.type].filter(Boolean).join(' · ') || '—'}</div><div className="detail-row"><span>JS Finder</span>{row.finding_type ? <Badge tone={jsFinder(row) === 'TruffleHog' ? 'server' : 'client'}>{jsFinder(row)}</Badge> : '—'}</div><div className="detail-row"><span>Classification</span>{row.finding_type ? <Badge tone={row.probable_vulnerability ? 'server' : 'warn'}>{row.probable_vulnerability ? 'Probable vulnerability' : 'Interesting lead'}</Badge> : '—'}</div><div className="detail-row"><span>JS Finding</span>{row.finding_type ? <><Badge tone={row.severity === 'high' ? 'server' : row.severity === 'medium' ? 'warn' : 'muted'}>{row.severity}</Badge><Badge>{row.finding_type}</Badge></> : '—'}</div><div className="detail-row"><span>Indicator</span>{row.indicator || '—'}</div><div className="detail-row"><span>Location</span>{row.line ? `Line ${row.line}${row.column ? `, column ${row.column}` : ''}` : '—'}</div><div className="detail-row"><span>Page URL</span>{row.page_url || '—'}</div><div className="detail-row"><span>Parameter</span>{row.param ? <><Badge tone={row.suspicious ? 'warn' : 'muted'}>{row.param}</Badge>{row.method && <Badge>{row.method}</Badge>}</> : '—'}</div><div className="detail-row"><span>Normalized Identity</span>{row.asset_key || row.normalized_path ? `${row.asset_key || ''}${row.normalized_path || ''}` : '—'}</div><div className="detail-row"><span>Param Reason</span>{row.reason || '—'}</div><div className="detail-row"><span>Sample Value</span>{row.sample_value || '—'}</div><div className="detail-row"><span>IP</span>{row.ip || '—'}</div><div className="detail-row"><span>Ports</span>{(row.ports || []).length ? (row.ports || []).join(', ') : '—'}</div><div className="detail-row"><span>ASN</span>{asn}</div><div className="detail-row"><span>CDN</span>{cdn}</div><div className="detail-row"><span>Title / Path</span>{row.title || row.path || row.base_url || row.matched_at || '—'}</div><div className="detail-row"><span>Redirect Chain</span>{row.redirect ? `${row.redirect.origin} → ${(row.redirect.hops || []).map(h => h.url).join(' → ') || row.redirect.final}` : '—'}</div><div className="detail-row"><span>Confidence</span>{row.confidence ? <Badge tone={row.confidence === 'confirmed' ? 'ok' : row.confidence === 'possible' ? 'warn' : row.confidence === 'filtered' ? 'client' : 'muted'}>{row.confidence}</Badge> : '—'}</div><div className="detail-row"><span>Noise / Novelty</span><Badge tone={(row.noise_score || 0) >= 50 ? 'client' : 'muted'}>Noise {row.noise_score || 0}</Badge><Badge tone={(row.novelty_score || 0) >= 50 ? 'ok' : 'muted'}>Novelty {row.novelty_score || 0}</Badge></div><div className="detail-row"><span>Observations</span>{row.observation_count || 1}</div><div className="detail-row"><span>Response Fingerprint</span>{row.fingerprint_id || row.content_hash || '—'}</div><div className="detail-row"><span>Size / Words / Lines</span>{[row.size && `${row.size} B`, row.words && `${row.words} words`, row.lines && `${row.lines} lines`].filter(Boolean).join(' · ') || '—'}</div><div className="detail-row"><span>Filtered Reason</span>{row.filtered_reason || '—'}</div><div className="detail-row"><span>Fingerprints</span><TechBadges tech={row.fingerprints} max={8}/></div><div className="detail-row"><span>Technologies</span><TechBadges tech={row.tech} max={8}/></div><div className="detail-row"><span>Tags</span>{tagsFor(row).map(t => <Badge key={t}>{t}</Badge>)}</div>{row.description && <div className="detail-block"><span>Description</span><pre>{row.description}</pre></div>}{(row.extracted_results || []).length > 0 && <div className="detail-block"><span>Extracted Results</span><pre>{(row.extracted_results || []).join('\n')}</pre></div>}{(row.references || []).length > 0 && <div className="detail-block"><span>References</span><pre>{(row.references || []).join('\n')}</pre></div>}{row.evidence && <div className="detail-block"><span>Evidence</span><pre>{row.evidence}</pre></div>}{row.file_path && <div className="detail-block"><span>Downloaded bundle</span><pre>{row.file_path}</pre></div>}{(row.variants || []).length > 1 && <div className="detail-block"><span>Equivalent observations</span><pre>{JSON.stringify(row.variants, null, 2)}</pre></div>}<div className="detail-block"><span>Response headers</span><pre>{JSON.stringify(row.response_headers || {}, null, 2)}</pre></div><div className="detail-block"><span>Headers sent</span><pre>{JSON.stringify(row.headers_sent || {}, null, 2)}</pre></div>{row.raw && <div className="detail-block"><span>Nuclei Raw</span><pre>{JSON.stringify(row.raw || {}, null, 2)}</pre></div>}<div className="detail-actions"><button onClick={() => window.open(openUrl(value), '_blank', 'noopener,noreferrer')}>Open</button><button onClick={() => navigator.clipboard?.writeText(value)}>Copy URL</button><button onClick={() => sendToPlayground(row)}>Send to Playground</button><button>Screenshot</button><button>Whois</button><button>Run Nuclei</button><button>Crawl</button><button onClick={() => markInteresting(row.kind, row)}>Mark</button></div></aside>;
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
    <nav className="landing-nav"><b>Recon Radar</b><div className="landing-actions"><button className="secondary" onClick={() => window.open('/playground', '_blank', 'noopener,noreferrer')}>Playground</button><button className="secondary" onClick={() => window.open('/security-lab', '_blank', 'noopener,noreferrer')}>Security Lab</button><button className="secondary" onClick={openSettings}>Settings</button><button className="secondary" onClick={() => window.open('/logs', '_blank', 'noopener,noreferrer')}>View Logs</button></div></nav>
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

function headerLinesToObject(text) {
  return Object.fromEntries((text || '').split('\n').map(line => {
    const [key, ...value] = line.split(':');
    return [key.trim(), value.join(':').trim()];
  }).filter(([key]) => key));
}

const SENSITIVE_HEADERS = new Set(['authorization', 'cookie', 'x-api-key', 'proxy-authorization']);
const STATIC_ASSET_RE = /\.(css|js|map|png|jpe?g|gif|svg|ico|webp|woff2?|ttf|eot|pdf|zip|tar|gz|rar|7z|mp4|mp3|avi|mov)$/i;

function objectToHeaderLines(headers = {}) {
  return Object.entries(headers || {}).map(([key, value]) => `${key}: ${value}`).join('\n');
}

function objectToHeaderRows(headers = {}) {
  const rows = Object.entries(headers || {}).map(([key, value]) => ({enabled: true, key, value, masked: SENSITIVE_HEADERS.has(String(key).toLowerCase())}));
  return rows.length ? rows : [{enabled: true, key: '', value: '', masked: false}];
}

function headerRowsToObject(rows = []) {
  return Object.fromEntries(rows.filter(r => r.enabled && r.key.trim()).map(r => [r.key.trim(), r.value]));
}

function maskedHeaders(headers = {}) {
  return Object.fromEntries(Object.entries(headers || {}).map(([key, value]) => [key, SENSITIVE_HEADERS.has(String(key).toLowerCase()) && value ? '••••••••' : value]));
}

function validHttpUrl(value) {
  try {
    const parsed = new URL(value);
    return ['http:', 'https:'].includes(parsed.protocol);
  } catch {
    return false;
  }
}

function urlParamNames(value) {
  try {
    return [...new URL(value).searchParams.keys()];
  } catch {
    return [];
  }
}

function bodyParamNames(body, bodyType) {
  if (!body || bodyType === 'none') return [];
  if (bodyType === 'form') return [...new URLSearchParams(body).keys()];
  if (bodyType === 'json') {
    try {
      const parsed = JSON.parse(body);
      return parsed && !Array.isArray(parsed) && typeof parsed === 'object' ? Object.keys(parsed) : [];
    } catch {
      return [];
    }
  }
  return [];
}

function hasTestableParameter(url, body, bodyType) {
  return urlParamNames(url).length > 0 || bodyParamNames(body, bodyType).length > 0;
}

function requestPath(value) {
  try {
    const u = new URL(value);
    return `${u.pathname || '/'}${u.search || ''}`;
  } catch {
    return value || '';
  }
}

function formatBytes(bytes = 0) {
  if (bytes > 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  if (bytes > 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${bytes || 0} B`;
}

function prettyBody(response) {
  const text = response?.response_body || '';
  const type = String(response?.content_type || response?.response_headers?.['content-type'] || response?.response_headers?.['Content-Type'] || '').toLowerCase();
  if (type.includes('json') || text.trim().startsWith('{') || text.trim().startsWith('[')) {
    try { return JSON.stringify(JSON.parse(text), null, 2); } catch {}
  }
  return text || 'No response yet.';
}

function makeCurl({method, url, headers, body, bodyType}) {
  const headerText = objectToHeaderLines(maskedHeaders(headers)).split('\n').filter(Boolean).map(h => `-H "${h}"`).join(' ');
  const data = body && bodyType !== 'none' ? `--data ${JSON.stringify(body)}` : '';
  return `curl -i -X ${method} ${headerText} ${data} "${url}"`.replace(/\s+/g, ' ').trim();
}

function redactSensitive(value) {
  if (Array.isArray(value)) return value.map(redactSensitive);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => {
      if (SENSITIVE_HEADERS.has(String(key).toLowerCase())) return [key, item ? '••••••••' : item];
      return [key, redactSensitive(item)];
    }));
  }
  return value;
}

function PlaygroundPage() {
  const seed = useMemo(() => {
    try { return JSON.parse(localStorage.getItem('playground.seed') || '{}'); } catch { return {}; }
  }, []);
  const queuedSeed = useMemo(() => {
    try { return JSON.parse(localStorage.getItem('playground.queue') || '[]'); } catch { return []; }
  }, []);
  const [method, setMethod] = useState(seed.method || 'GET');
  const [url, setUrl] = useState(seed.url || '');
  const [headerMode, setHeaderMode] = useState('table');
  const [headerRows, setHeaderRows] = useState(objectToHeaderRows(seed.headers || {}));
  const [rawHeaders, setRawHeaders] = useState(objectToHeaderLines(seed.headers || {}));
  const [bodyType, setBodyType] = useState(seed.body_type || (seed.body ? 'raw' : 'none'));
  const [body, setBody] = useState(seed.body || '');
  const [timeout, setTimeoutValue] = useState(20);
  const [followRedirects, setFollowRedirects] = useState(true);
  const [response, setResponse] = useState(null);
  const [responseTab, setResponseTab] = useState('Pretty');
  const [bodySearch, setBodySearch] = useState('');
  const [history, setHistory] = useState([]);
  const [historyOpen, setHistoryOpen] = useState(true);
  const [toolRuns, setToolRuns] = useState([]);
  const [selectedParams, setSelectedParams] = useState({});
  const [importedRequests, setImportedRequests] = useState(Array.isArray(queuedSeed) ? queuedSeed : []);
  const [busy, setBusy] = useState('');
  const [alert, setAlert] = useState('');
  const [urlTouched, setUrlTouched] = useState(Boolean(seed.url));
  const [campaignOpen, setCampaignOpen] = useState(false);
  const [payloadText, setPayloadText] = useState('');
  const [campaignKind, setCampaignKind] = useState('xss');
  const [campaignDelay, setCampaignDelay] = useState(250);
  const [campaignRate, setCampaignRate] = useState(2);
  const [campaignProxies, setCampaignProxies] = useState('');
  const [campaignAuthorized, setCampaignAuthorized] = useState(false);
  const [campaignResult, setCampaignResult] = useState(null);

  const refreshHistory = useCallback(() => j(`${API}/playground/history?limit=40`).then(r => setHistory(r.items || [])).catch(() => {}), []);
  useEffect(() => { refreshHistory(); }, [refreshHistory]);
  useEffect(() => {
    if (seed.url) localStorage.removeItem('playground.seed');
    if (queuedSeed.length) localStorage.removeItem('playground.queue');
  }, [seed.url, queuedSeed.length]);
  useEffect(() => {
    if (headerMode === 'table') setRawHeaders(objectToHeaderLines(headerRowsToObject(headerRows)));
  }, [headerRows, headerMode]);

  const headersObject = headerMode === 'raw' ? headerLinesToObject(rawHeaders) : headerRowsToObject(headerRows);
  const urlValid = validHttpUrl(url);
  const urlError = (urlTouched || alert) && url && !urlValid ? 'Playground URL must be an absolute http or https URL.' : '';
  const arjunDisabled = !urlValid || Boolean(busy) || STATIC_ASSET_RE.test(new URL(urlValid ? url : 'https://placeholder.invalid/').pathname) || !['GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS'].includes(method);
  const dalfoxReason = !urlValid ? 'Enter a valid absolute URL first.' : !hasTestableParameter(url, body, bodyType) ? 'No testable parameter found. Run Arjun first or add a parameter manually.' : '';
  const dalfoxDisabled = Boolean(busy) || Boolean(dalfoxReason) || !['GET','POST','PUT','PATCH','DELETE'].includes(method);

  async function send(save = true) {
    setUrlTouched(true); setAlert('');
    if (!urlValid) return;
    setBusy('request');
    try {
      const payload = {method, url, headers: headersObject, body: bodyType === 'none' ? '' : body, body_type: bodyType, timeout: Number(timeout) || 20, follow_redirects: followRedirects, save};
      const res = await j(`${API}/playground/request`, {method: 'POST', body: JSON.stringify(payload)});
      setResponse(res.item);
      await refreshHistory();
    } catch (err) {
      setAlert(err.message || String(err));
    } finally {
      setBusy('');
    }
  }

  function loadItem(item) {
    setMethod(item.method || 'GET');
    setUrl(item.url || '');
    setUrlTouched(true);
    setHeaderRows(objectToHeaderRows(item.request_headers || {}));
    setRawHeaders(objectToHeaderLines(item.request_headers || {}));
    setBody(item.request_body || '');
    setBodyType(item.request_body ? 'raw' : 'none');
    setResponse(item);
  }

  function loadImportedRequest(item) {
    setMethod(item.method || 'GET');
    setUrl(item.url || '');
    setUrlTouched(true);
    setHeaderRows(objectToHeaderRows(item.headers || {}));
    setRawHeaders(objectToHeaderLines(item.headers || {}));
    setBody(item.body || '');
    setBodyType(item.body_type || (item.body ? 'raw' : 'none'));
    setResponse(null);
  }

  function updateHeaderRow(index, patch) {
    setHeaderRows(rows => rows.map((row, i) => i === index ? {...row, ...patch, masked: patch.key !== undefined ? SENSITIVE_HEADERS.has(String(patch.key).toLowerCase()) : row.masked} : row));
  }

  function requestWithSelectedParams(params) {
    const chosen = (params || discoveredParams).filter(p => selectedParams[`${p.method || 'GET'}:${p.param}`]);
    if (!chosen.length) return {url, body, bodyType};
    if (['POST','PUT','PATCH'].includes(method) && bodyType === 'json') {
      let parsed = {};
      try { parsed = body ? JSON.parse(body) : {}; } catch { parsed = {}; }
      chosen.forEach(p => { if (!Object.prototype.hasOwnProperty.call(parsed, p.param)) parsed[p.param] = 'test'; });
      return {url, body: JSON.stringify(parsed, null, 2), bodyType};
    }
    if (['POST','PUT','PATCH'].includes(method) && bodyType === 'form') {
      const data = new URLSearchParams(body || '');
      chosen.forEach(p => { if (!data.has(p.param)) data.set(p.param, 'test'); });
      return {url, body: data.toString(), bodyType};
    }
    try {
      const next = new URL(url);
      chosen.forEach(p => { if (!next.searchParams.has(p.param)) next.searchParams.set(p.param, 'test'); });
      return {url: next.toString(), body, bodyType};
    } catch {}
    return {url, body, bodyType};
  }

  function addSelectedToRequest(params) {
    const next = requestWithSelectedParams(params);
    setUrl(next.url);
    setBody(next.body);
    setBodyType(next.bodyType);
    setUrlTouched(true);
  }

  async function runTool(tool, params = null) {
    setUrlTouched(true); setAlert('');
    const request = tool === 'dalfox' && params ? requestWithSelectedParams(params) : {url, body, bodyType};
    if (tool === 'dalfox' && params) {
      setUrl(request.url);
      setBody(request.body);
      setBodyType(request.bodyType);
    }
    if (!validHttpUrl(request.url)) return;
    if (tool === 'dalfox' && !hasTestableParameter(request.url, request.body, request.bodyType)) {
      setAlert('No testable parameter found. Run Arjun first or add a parameter manually.');
      return;
    }
    const id = `${tool}-${Date.now()}`;
    const run = {id, tool, status: 'running', startedAt: new Date().toISOString(), logs: '', request: {method, url: request.url, headers: maskedHeaders(headersObject), body: request.bodyType === 'none' ? '' : request.body, body_type: request.bodyType}, parameters: [], findings: []};
    setToolRuns(runs => [run, ...runs]);
    setBusy(tool);
    try {
      const payload = {method, url: request.url, headers: headersObject, body: request.bodyType === 'none' ? '' : request.body, body_type: request.bodyType, timeout: tool === 'dalfox' ? 180 : 120, arjun_methods: method};
      const result = await j(`${API}/playground/${tool}`, {method: 'POST', body: JSON.stringify(payload)});
      const paramsFound = (result.parameters || []).map(p => ({...p, param: p.param || p.name, method: p.method || p.location || method}));
      if (tool === 'arjun') {
        const selected = {};
        paramsFound.forEach(p => { selected[`${p.method || 'GET'}:${p.param}`] = true; });
        setSelectedParams(selected);
      }
      setToolRuns(runs => runs.map(item => item.id === id ? {...item, status: 'completed', completedAt: new Date().toISOString(), elapsedMs: Date.now() - new Date(run.startedAt).getTime(), logs: JSON.stringify(redactSensitive(result.raw || result), null, 2), parameters: paramsFound, findings: result.findings || [], result} : item));
    } catch (err) {
      setToolRuns(runs => runs.map(item => item.id === id ? {...item, status: 'failed', completedAt: new Date().toISOString(), elapsedMs: Date.now() - new Date(run.startedAt).getTime(), logs: err.message || String(err)} : item));
    } finally {
      setBusy('');
    }
  }

  async function runPayloadCampaign() {
    setAlert(''); setCampaignResult(null);
    if (!campaignAuthorized) { setAlert('Confirm that you are authorized to test this target.'); return; }
    const payloads = payloadText.split(/\r?\n/).map(v => v.trim()).filter(v => v && !v.startsWith('#'));
    if (!payloads.length) { setAlert('Load or paste at least one payload.'); return; }
    if (!url.includes('{{PAYLOAD}}') && !body.includes('{{PAYLOAD}}')) { setAlert('Place {{PAYLOAD}} in the URL or request body.'); return; }
    setBusy('payload campaign');
    try {
      const result = await j(`${API}/playground/payload-campaign`, {method: 'POST', body: JSON.stringify({
        method, url_template: url, headers: headersObject, body_template: bodyType === 'none' ? '' : body,
        body_type: bodyType, payloads, delay_ms: Number(campaignDelay) || 0,
        rate_limit_per_second: Number(campaignRate) || 1, timeout: Number(timeout) || 20,
        proxies: campaignProxies.split(/\r?\n/).map(v => v.trim()).filter(Boolean), follow_redirects: followRedirects,
        time_threshold_ms: campaignKind === 'sqli' ? 3000 : 10000,
      })});
      setCampaignResult(result);
    } catch (err) { setAlert(err.message || String(err)); }
    finally { setBusy(''); }
  }

  const statusTone = response?.error ? 'server' : response?.status_code ? statusClass(response.status_code) : 'muted';
  const discoveredParams = toolRuns.find(r => r.tool === 'arjun' && r.parameters?.length)?.parameters || [];
  const displayBody = responseTab === 'Pretty' ? prettyBody(response) : responseTab === 'Raw' ? (response?.response_body || 'No response yet.') : (response?.response_body || 'No response yet.');
  const filteredBody = bodySearch ? displayBody.split('\n').filter(line => line.toLowerCase().includes(bodySearch.toLowerCase())).join('\n') || 'No matches.' : displayBody;
  return <div className="playground-page">
    <header className="playground-header"><div className="brand"><h1>Playground</h1><div className="header-meta"><Badge tone="redirect">Repeater</Badge><span>Manual request testing and focused tools</span></div></div><div className="runbox"><button className="secondary" onClick={() => window.location.href = '/'}>Dashboard</button><button className="secondary" onClick={() => window.location.href = '/security-lab'}>Security Lab</button><button className="secondary" onClick={refreshHistory}>Refresh history</button></div></header>
    {alert && <div className="alert">{alert}</div>}
    <main className={`playground-layout ${historyOpen ? '' : 'history-collapsed'}`}>
      <section className="playground-compose">
        {importedRequests.length > 0 && <div className="playground-imports"><div className="panel-title"><span>Imported from pipeline</span><Badge tone="ok">{importedRequests.length}</Badge><button onClick={() => setImportedRequests([])}>Clear</button></div>{importedRequests.map((item, index) => <button key={`${item.url}-${index}`} className={item.url === url ? 'active' : ''} onClick={() => loadImportedRequest(item)}><b>{item.method || 'GET'} {hostFromUrl(item.url)}</b><span>{item.label || item.source || requestPath(item.url)}</span><small>{item.url}</small></button>)}</div>}
        <div className="playground-urlbar"><select value={method} onChange={e => setMethod(e.target.value)}>{['GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS'].map(m => <option key={m}>{m}</option>)}</select><input value={url} onBlur={() => setUrlTouched(true)} onChange={e => { setUrl(e.target.value); setAlert(''); }} placeholder="https://target/path?param=value"/><button className="primary" disabled={!url || busy === 'request'} onClick={() => send(true)}>{busy === 'request' ? 'Sending...' : 'Send'}</button></div>
        {urlError && <div className="inline-alert">{urlError}</div>}
        <div className="editor-head"><b>Headers</b><div className="segmented"><button className={headerMode === 'table' ? 'sel' : ''} onClick={() => setHeaderMode('table')}>Key/value</button><button className={headerMode === 'raw' ? 'sel' : ''} onClick={() => setHeaderMode('raw')}>Raw headers</button></div></div>
        {headerMode === 'table' ? <div className="header-grid"><span>On</span><span>Header</span><span>Value</span><span></span>{headerRows.map((row, index) => <React.Fragment key={index}><input type="checkbox" checked={row.enabled} onChange={e => updateHeaderRow(index, {enabled: e.target.checked})}/><input value={row.key} onChange={e => updateHeaderRow(index, {key: e.target.value})} placeholder="Authorization"/><input type={row.masked ? 'password' : 'text'} value={row.value} onChange={e => updateHeaderRow(index, {value: e.target.value})} placeholder="Bearer ..."/><button onClick={() => setHeaderRows(rows => rows.filter((_, i) => i !== index))}>Delete</button></React.Fragment>)}<button className="secondary" onClick={() => setHeaderRows(rows => [...rows, {enabled: true, key: '', value: '', masked: false}])}>Add header</button></div> : <textarea className="raw-editor" value={rawHeaders} onChange={e => setRawHeaders(e.target.value)} placeholder="Header: value"/>}
        <div className="body-controls"><label>Body type <select value={bodyType} onChange={e => setBodyType(e.target.value)}>{[['none','None'],['form','Form URL encoded'],['json','JSON'],['raw','Raw']].map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label></div>
        {bodyType !== 'none' && <textarea className="body-editor" value={body} onChange={e => setBody(e.target.value)} placeholder={bodyType === 'json' ? '{\n  "username": "test"\n}' : bodyType === 'form' ? 'username=test&redirect=/home' : 'Raw request body'}/>}
        <div className="playground-actions"><label>Timeout <input type="number" min="1" max="120" value={timeout} onChange={e => setTimeoutValue(e.target.value)}/></label><label><input type="checkbox" checked={followRedirects} onChange={e => setFollowRedirects(e.target.checked)}/> Follow redirects</label><button onClick={() => navigator.clipboard?.writeText(makeCurl({method, url, headers: headersObject, body, bodyType}))}>Copy curl</button></div>
        <div className="focused-tools"><b>Focused tools</b><button onClick={() => runTool('arjun')} disabled={arjunDisabled}><span>Discover Parameters</span><small>Arjun</small></button><button onClick={() => runTool('dalfox')} disabled={dalfoxDisabled} title={dalfoxReason}><span>Scan for XSS</span><small>Dalfox</small></button><button onClick={() => setCampaignOpen(!campaignOpen)}><span>Payload campaign</span><small>XSS / SQLi lists</small></button>{dalfoxReason && urlValid && <p className="hint">{dalfoxReason}</p>}</div>
        {campaignOpen && <div className="campaign-panel"><div className="panel-title"><span>Payload campaign</span><Badge tone="warn">Manual · authorized targets only</Badge></div><p className="hint">Put <code>{'{{PAYLOAD}}'}</code> in the URL or body. A clean baseline is compared with every response; a status/size change alone is reported as an anomaly, not a finding.</p><div className="campaign-grid"><label>Payload type<select value={campaignKind} onChange={e => setCampaignKind(e.target.value)}><option value="xss">XSS</option><option value="sqli">SQL injection</option></select></label><label>Time gap (ms)<input type="number" min="0" max="10000" value={campaignDelay} onChange={e => setCampaignDelay(e.target.value)}/></label><label>Rate limit / second<input type="number" min="0.1" max="50" step="0.1" value={campaignRate} onChange={e => setCampaignRate(e.target.value)}/></label></div><label className="file-button">Load payload .txt<input type="file" accept=".txt,text/plain" onChange={async e => setPayloadText(e.target.files?.[0] ? await e.target.files[0].text() : '')}/></label><textarea className="body-editor" value={payloadText} onChange={e => setPayloadText(e.target.value)} placeholder="One payload per line"/><textarea className="raw-editor compact" value={campaignProxies} onChange={e => setCampaignProxies(e.target.value)} placeholder={'Optional proxy rotation, one URL per line\nhttp://127.0.0.1:8080'}/><label><input type="checkbox" checked={campaignAuthorized} onChange={e => setCampaignAuthorized(e.target.checked)}/> I am authorized to test this target and accept the configured request rate.</label><button className="primary" disabled={Boolean(busy) || !campaignAuthorized} onClick={runPayloadCampaign}>{busy === 'payload campaign' ? 'Testing payloads…' : `Run ${payloadText.split(/\r?\n/).filter(Boolean).length || 0} payloads`}</button></div>}
      </section>
      <section className="playground-response">
        <div className="panel-title"><span>Response</span>{response && <><Badge tone={statusTone}>{response.error ? 'error' : response.status_code || 'sent'}</Badge><em>{response.duration_ms || 0} ms</em><em>{formatBytes(response.response_size)}</em></>}</div>
        {response?.error && <div className="inline-alert">{response.error}</div>}
        {response && <div className="response-meta"><span>Status: {response.status_code || 'n/a'}</span><span>Time: {response.duration_ms || 0} ms</span><span>Size: {formatBytes(response.response_size)}</span><span>Content-Type: {response.content_type || response.response_headers?.['content-type'] || 'n/a'}</span><span>Final URL: {response.final_url || response.url}</span><span>Redirects: {response.redirect_count || 0}</span>{response.truncated && <Badge tone="warn">truncated</Badge>}</div>}
        <div className="response-toolbar"><div className="segmented">{['Pretty','Raw','Preview'].map(tab => <button key={tab} className={responseTab === tab ? 'sel' : ''} onClick={() => setResponseTab(tab)}>{tab}</button>)}</div><input placeholder="Search body" value={bodySearch} onChange={e => setBodySearch(e.target.value)}/></div>
        <div className="response-tabs"><div><b>Headers</b><pre>{JSON.stringify(response?.response_headers || {}, null, 2)}</pre></div><div><b>{responseTab === 'Preview' ? 'Sandboxed text preview' : 'Body'}</b><pre>{filteredBody}</pre></div></div>
        {discoveredParams.length > 0 && <div className="discovered-params"><div className="panel-title"><span>Discovered parameters</span><Badge tone="ok">{discoveredParams.length}</Badge></div>{discoveredParams.map(p => <label key={`${p.method}:${p.param}`}><input type="checkbox" checked={Boolean(selectedParams[`${p.method || 'GET'}:${p.param}`])} onChange={e => setSelectedParams(s => ({...s, [`${p.method || 'GET'}:${p.param}`]: e.target.checked}))}/><b>{p.param}</b><span>{p.method || 'GET'}</span></label>)}<div className="playground-actions"><button onClick={() => addSelectedToRequest(discoveredParams)}>Add selected to request</button><button onClick={() => runTool('dalfox', discoveredParams)} disabled={busy}>Run Dalfox on selected</button><button onClick={() => navigator.clipboard?.writeText(discoveredParams.map(p => `${p.param}\t${p.method || 'GET'}`).join('\n'))}>Copy results</button></div></div>}
        <div className="tool-runs"><div className="panel-title"><span>Tool Runs</span><Badge tone={busy ? 'redirect' : 'muted'}>{busy || 'idle'}</Badge></div>{toolRuns.length ? toolRuns.map(run => <div className="tool-card" key={run.id}><div><b>{run.tool === 'arjun' ? 'Arjun' : 'Dalfox'}</b><Badge tone={run.status === 'completed' ? 'ok' : run.status === 'failed' ? 'server' : 'redirect'}>{run.status}</Badge></div><p><span>Started: {new Date(run.startedAt).toLocaleTimeString()}</span><span>Elapsed: {Math.round((run.elapsedMs || (Date.now() - new Date(run.startedAt).getTime())) / 1000)}s</span><span>{run.tool === 'arjun' ? `Parameters found: ${run.parameters?.length || 0}` : `Findings: ${run.findings?.length || 0}`}</span></p><div className="playground-actions"><button onClick={() => navigator.clipboard?.writeText(makeCurl({method: run.request.method, url: run.request.url, headers: run.request.headers, body: run.request.body, bodyType: run.request.body_type}))}>View command</button><button onClick={() => navigator.clipboard?.writeText(run.logs || '')}>Copy output</button></div><pre>{run.logs || 'Queued.'}</pre></div>) : <p className="muted">Run Arjun or Dalfox on the current request.</p>}</div>
        {campaignResult && <div className="campaign-results"><div className="panel-title"><span>Payload results</span><Badge tone={campaignResult.summary.found ? 'server' : 'ok'}>{campaignResult.summary.found} found / {campaignResult.summary.tested} tested</Badge></div><div className="campaign-result-list">{campaignResult.results.map(row => <div className={`campaign-result ${row.found ? 'found' : ''}`} key={row.index}><span>{row.found ? 'FOUND' : row.error ? 'ERROR' : 'Not found'}</span><code>{row.payload}</code><small>{row.status || '—'} · {row.duration_ms} ms · {row.size} B</small><p>{row.evidence.join(' · ') || row.error || 'No strong evidence compared with baseline.'}</p></div>)}</div></div>}
      </section>
      <aside className="playground-history"><div className="panel-title"><span>History</span><button onClick={() => setHistoryOpen(!historyOpen)}>{historyOpen ? 'Collapse' : 'Expand'}</button></div>{historyOpen && <><div className="playground-actions"><button onClick={() => setHistory([])}>Clear history</button></div>{history.length ? history.map(item => <div className="history-card" key={item.id}><button onClick={() => loadItem(item)}><b>{item.method} {requestPath(item.url)}</b><span>{item.status_code || item.error || 'sent'} · {item.duration_ms || 0} ms · {ago(item.created_at)}</span><small>{hostFromUrl(item.url)}</small></button><div><button onClick={() => loadItem(item)}>Pin item</button><button onClick={() => setHistory(items => items.filter(x => x.id !== item.id))}>Delete item</button></div></div>) : <p className="muted">No requests yet.</p>}</>}</aside>
    </main>
  </div>;
}

function parseJsonInput(value, fallback = {}) {
  try { return JSON.parse(value || JSON.stringify(fallback)); } catch { throw new Error('One of the JSON editors contains invalid JSON.'); }
}

const LAB_ROLES = ['anonymous', 'normal user', 'privileged user', 'organization member', 'organization administrator'];

function SecurityLabPage() {
  const [tab, setTab] = useState('API inventory');
  const [busy, setBusy] = useState('');
  const [alert, setAlert] = useState('');
  const [result, setResult] = useState(null);
  const [artifactType, setArtifactType] = useState('auto');
  const [artifact, setArtifact] = useState('');
  const [observed, setObserved] = useState('[]');
  const [cases, setCases] = useState(LAB_ROLES.map((role, index) => ({role, session: index === 1 ? 'Account A' : index === 2 ? 'Account B' : '', status: role === 'anonymous' ? 401 : 200, body: '{}'})));
  const [property, setProperty] = useState({original: '{\n  "name": "Alice",\n  "role": "user"\n}', attempted: '{\n  "name": "Alice",\n  "role": "admin",\n  "isAdmin": true\n}', response: '{}', readOnly: 'role,isAdmin'});
  const [ws, setWs] = useState({url: '', aHeaders: '{}', bHeaders: '{}', messages: '{"type":"get","id":"123"}'});
  const [upload, setUpload] = useState({file: null, mime: '', retrieval: '[]', location: ''});

  async function call(path, payload) {
    setBusy(path); setAlert(''); setResult(null);
    try { setResult(await j(`${API}${path}`, {method: 'POST', body: JSON.stringify(payload)})); }
    catch (err) { setAlert(err.message || String(err)); }
    finally { setBusy(''); }
  }

  async function parseArtifact() {
    const parsed = await j(`${API}/security/artifacts/parse`, {method: 'POST', body: JSON.stringify({content: artifact, artifact_type: artifactType, source: 'security-lab'})});
    if (observed.trim() !== '[]') {
      const compared = await j(`${API}/security/endpoints/compare`, {method: 'POST', body: JSON.stringify({documented: parsed.endpoints || [], observed: parseJsonInput(observed, [])})});
      setResult({...parsed, comparison: compared});
    } else setResult(parsed);
  }

  async function analyzeUploadFile() {
    if (!upload.file) { setAlert('Choose an upload sample first.'); return; }
    const content = await new Promise((resolve, reject) => { const reader = new FileReader(); reader.onload = () => resolve(String(reader.result).split(',')[1] || ''); reader.onerror = reject; reader.readAsDataURL(upload.file); });
    await call('/security/uploads/analyze', {filename: upload.file.name, declared_mime: upload.mime || upload.file.type || 'application/octet-stream', content_base64: content, response: {url: upload.location}, retrieval_cases: parseJsonInput(upload.retrieval, [])});
  }

  const updateCase = (index, patch) => setCases(rows => rows.map((row, i) => i === index ? {...row, ...patch} : row));
  const authPayload = () => ({cases: cases.map(row => ({...row, body: parseJsonInput(row.body)}))});
  const tabs = ['API inventory', 'Authorization', 'Properties', 'WebSockets', 'File uploads'];
  return <div className="security-lab"><header className="playground-header"><div className="brand"><h1>Security Lab</h1><div className="header-meta"><Badge tone="client">Evidence workspace</Badge><span>API, OAuth, GraphQL, authorization, WebSocket, and upload testing</span></div></div><div className="runbox"><button onClick={() => window.location.href = '/'}>Dashboard</button><button onClick={() => window.location.href = '/playground'}>Playground</button></div></header>
    {alert && <div className="alert">{alert}</div>}
    <div className="lab-tabs">{tabs.map(name => <button key={name} className={tab === name ? 'sel' : ''} onClick={() => {setTab(name); setResult(null);}}>{name}</button>)}</div>
    <main className="lab-layout"><section className="lab-editor">
      {tab === 'API inventory' && <><h2>Unified endpoint inventory</h2><p>Parse OpenAPI/Swagger, Postman, GraphQL introspection, mobile config, source maps, or JavaScript. JS results separate API bases, route templates, WebSockets, flags, environments, GraphQL operations, OAuth configuration, and traced DOM flows.</p><div className="editor-head"><select value={artifactType} onChange={e => setArtifactType(e.target.value)}>{['auto','openapi','swagger','postman','graphql','mobile-config','source-map','javascript'].map(v => <option key={v}>{v}</option>)}</select><label className="file-button">Load artifact<input type="file" onChange={async e => setArtifact(e.target.files?.[0] ? await e.target.files[0].text() : '')}/></label></div><textarea className="lab-code" value={artifact} onChange={e => setArtifact(e.target.value)} placeholder="Paste or load an API artifact or JavaScript bundle"/><label>Observed endpoints (JSON array)<textarea className="lab-code small" value={observed} onChange={e => setObserved(e.target.value)} placeholder='[{"method":"GET","path":"/api/users/123"}]'/></label><button className="primary" disabled={Boolean(busy) || !artifact} onClick={async () => {setBusy('parse'); setAlert(''); try {await parseArtifact();} catch (e) {setAlert(e.message);} finally {setBusy('');}}}>Parse and compare</button></>}
      {tab === 'Authorization' && <><h2>Role and two-account matrix</h2><p>Record the same request/GraphQL operation under Account A, Account B, and each application role. Object identifiers and returned-field differences are extracted automatically.</p><div className="auth-cases">{cases.map((row, index) => <div className="auth-case" key={row.role}><b>{row.role}</b><input value={row.session} onChange={e => updateCase(index, {session: e.target.value})} placeholder="Account A / B"/><input type="number" value={row.status} onChange={e => updateCase(index, {status: Number(e.target.value)})}/><input value={row.operation || ''} onChange={e => updateCase(index, {operation: e.target.value})} placeholder="GraphQL operation / request label"/><textarea value={row.body} onChange={e => updateCase(index, {body: e.target.value})} placeholder="Response JSON"/></div>)}</div><div className="playground-actions"><button className="primary" onClick={() => call('/security/authorization/compare', authPayload())}>Compare REST responses</button><button onClick={() => call('/security/graphql/matrix', authPayload())}>Build GraphQL matrix</button></div></>}
      {tab === 'Properties' && <><h2>Mass-assignment and property authorization</h2><p>Compare the original object, attempted write, and server response. Mark read-only properties to detect accepted privileged fields.</p>{[['original','Original object'],['attempted','Attempted write'],['response','Server response']].map(([key,label]) => <label key={key}>{label}<textarea className="lab-code small" value={property[key]} onChange={e => setProperty({...property, [key]: e.target.value})}/></label>)}<label>Read-only fields<input value={property.readOnly} onChange={e => setProperty({...property, readOnly: e.target.value})} placeholder="role,isAdmin,ownerId"/></label><button className="primary" onClick={() => call('/security/properties/compare', {original: parseJsonInput(property.original), attempted: parseJsonInput(property.attempted), response: parseJsonInput(property.response), read_only: property.readOnly.split(',').map(v => v.trim()).filter(Boolean)})}>Compare properties</button></>}
      {tab === 'WebSockets' && <><h2>Two-session WebSocket repeater</h2><p>Replay the same messages in two authenticated sessions and compare replies for authorization differences.</p><label>WebSocket URL<input value={ws.url} onChange={e => setWs({...ws, url: e.target.value})} placeholder="wss://target.example/ws"/></label><div className="two-col"><label>Account A headers<textarea value={ws.aHeaders} onChange={e => setWs({...ws, aHeaders: e.target.value})}/></label><label>Account B headers<textarea value={ws.bHeaders} onChange={e => setWs({...ws, bHeaders: e.target.value})}/></label></div><label>Messages, one per line<textarea className="lab-code small" value={ws.messages} onChange={e => setWs({...ws, messages: e.target.value})}/></label><button className="primary" onClick={() => call('/security/websockets/compare', {url: ws.url, sessions: [{label: 'Account A', headers: parseJsonInput(ws.aHeaders), messages: ws.messages.split(/\r?\n/).filter(Boolean)}, {label: 'Account B', headers: parseJsonInput(ws.bHeaders), messages: ws.messages.split(/\r?\n/).filter(Boolean)}]})}>Replay both sessions</button></>}
      {tab === 'File uploads' && <><h2>File-upload analysis</h2><p>Compare extension, declared MIME, sniffed content, storage domain, generated filename, and retrieval authorization cases.</p><label className="file-button">Choose sample<input type="file" onChange={e => setUpload({...upload, file: e.target.files?.[0] || null})}/></label><label>Declared MIME<input value={upload.mime} onChange={e => setUpload({...upload, mime: e.target.value})} placeholder="image/jpeg"/></label><label>Returned storage URL<input value={upload.location} onChange={e => setUpload({...upload, location: e.target.value})} placeholder="https://cdn.example/file.jpg"/></label><label>Retrieval cases (JSON)<textarea className="lab-code small" value={upload.retrieval} onChange={e => setUpload({...upload, retrieval: e.target.value})} placeholder='[{"role":"Account B","status":200,"body":{}}]'/></label><button className="primary" onClick={analyzeUploadFile}>Analyze upload evidence</button></>}
    </section><section className="lab-results"><div className="panel-title"><span>Analysis result</span>{busy && <Badge tone="redirect">Working…</Badge>}</div>{result ? <pre>{JSON.stringify(result, null, 2)}</pre> : <div className="lab-empty"><b>No analysis yet</b><span>Run the active workspace to see normalized evidence and findings.</span></div>}</section></main>
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
  async function runNucleiOnRows(rows) {
    const parentScanId = result?.active_scan?.id || scan?.id;
    const urls = [...new Set((rows || []).map(nucleiUrlForRow).filter(Boolean))];
    if (!parentScanId || !urls.length) return;
    setAlert('');
    try {
      const payload = {
        stage: 'nuclei',
        subset_urls: urls,
        run_nuclei: true,
        nuclei_profile: opts.nuclei_profile || 'light',
        nuclei_severity: opts.nuclei_severity || 'high,critical',
        nuclei_tags: opts.nuclei_tags || 'exposure,takeover',
        nuclei_exclude_tags: opts.nuclei_exclude_tags || 'dos,fuzz,intrusive,brute-force,bruteforce,slow',
        nuclei_types: opts.nuclei_types || 'http',
        nuclei_templates: opts.nuclei_templates || '',
        nuclei_concurrency: Number(opts.nuclei_concurrency) || 10,
        nuclei_rate_limit: Number(opts.nuclei_rate_limit) || 25,
        nuclei_timeout: Number(opts.nuclei_timeout) || 4,
        nuclei_retries: Number(opts.nuclei_retries) || 0,
        nuclei_stage_timeout: Number(opts.nuclei_stage_timeout) || 300,
        nuclei_max_urls: urls.length,
        nuclei_no_interactsh: opts.nuclei_no_interactsh !== false,
        nuclei_include_content_paths: false,
      };
      const res = await j(`${API}/scans/${parentScanId}/rerun`, {method: 'POST', body: JSON.stringify(payload)});
      setScan({id: res.scan_id, status: 'queued', stage: 'queued:nuclei'});
      setSelectedIds(new Set());
      setAlert(`Queued focused Nuclei for ${urls.length} selected URL${urls.length === 1 ? '' : 's'}.`);
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
  const nucleiCandidateRows = tab === 'Live Hosts' ? httpRows : tab === 'Content Paths' ? dirRows : tab === 'JS Intel' ? jsRows : tab === 'Parameters' ? parameterRows : tab === 'Arjun' ? arjunRows : [];
  const selectedNucleiRows = nucleiCandidateRows.filter(r => selectedIds.has(r.id) && nucleiUrlForRow(r));
  const showNucleiAction = ['Live Hosts', 'Content Paths', 'JS Intel', 'Parameters', 'Arjun'].includes(tab);
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
    <SidebarGroup title="FFUF Options"><label><input type="checkbox" checked={opts.run_ffuf} onChange={e => setOpts({...opts, run_ffuf: e.target.checked})}/> Run directory discovery</label><select value={opts.ffuf_mode} onChange={e => setOpts({...opts, ffuf_mode: e.target.value})}><option value="tech">Tech-specific only</option><option value="combined">Tech-specific + generic</option><option value="generic">Generic only</option></select>{runError && <p className="inline-alert">{runError}</p>}<input placeholder="extensions php,txt" onChange={e => setOpts({...opts, extensions: e.target.value})}/><input placeholder="match codes" value={opts.ffuf_match_codes} onChange={e => setOpts({...opts, ffuf_match_codes: e.target.value})}/><input placeholder="host timeout seconds" value={opts.ffuf_host_timeout} onChange={e => setOpts({...opts, ffuf_host_timeout: e.target.value})}/><input placeholder="max FFUF hosts (blank = all)" value={opts.max_ffuf_hosts || ''} onChange={e => setOpts({...opts, max_ffuf_hosts: e.target.value ? Number(e.target.value) : null})}/><label><input type="checkbox" checked={opts.ffuf_auto_calibration} onChange={e => setOpts({...opts, ffuf_auto_calibration: e.target.checked})}/> Auto calibration (-ac)</label><label><input type="checkbox" checked={opts.ffuf_recursive} onChange={e => setOpts({...opts, ffuf_recursive: e.target.checked})}/> Recursive</label><p className="hint">Tech-specific mode uses small focused wordlists based on fingerprints and response headers.</p></SidebarGroup>
    <SidebarGroup title="Nuclei"><div className="option-stack"><span className="setting-label">Focused template scan</span><label><input type="checkbox" checked={opts.run_nuclei} onChange={e => setOpts({...opts, run_nuclei: e.target.checked})}/> Include Nuclei in full scans</label><select value={opts.nuclei_profile} onChange={e => setOpts({...opts, nuclei_profile: e.target.value})}><option value="light">Light and fast</option><option value="balanced">Balanced</option><option value="full">Full selected severities</option></select><label><input type="checkbox" checked={opts.nuclei_no_interactsh} onChange={e => setOpts({...opts, nuclei_no_interactsh: e.target.checked})}/> Disable Interactsh/OAST checks</label><label><input type="checkbox" checked={opts.nuclei_include_content_paths} onChange={e => setOpts({...opts, nuclei_include_content_paths: e.target.checked})}/> Include discovered content paths in full scans</label><input placeholder="severity high,critical" value={opts.nuclei_severity} onChange={e => setOpts({...opts, nuclei_severity: e.target.value || 'high,critical'})}/><input placeholder="include tags exposure,takeover" value={opts.nuclei_tags} onChange={e => setOpts({...opts, nuclei_tags: e.target.value})}/><input placeholder="protocol types http" value={opts.nuclei_types} onChange={e => setOpts({...opts, nuclei_types: e.target.value})}/><input placeholder="exclude tags dos,fuzz,intrusive" value={opts.nuclei_exclude_tags} onChange={e => setOpts({...opts, nuclei_exclude_tags: e.target.value})}/><input placeholder="specific templates or ids, comma-separated" value={opts.nuclei_templates} onChange={e => setOpts({...opts, nuclei_templates: e.target.value})}/><input placeholder="concurrency" value={opts.nuclei_concurrency} onChange={e => setOpts({...opts, nuclei_concurrency: Number(e.target.value) || 10})}/><input placeholder="rate limit req/s" value={opts.nuclei_rate_limit} onChange={e => setOpts({...opts, nuclei_rate_limit: Number(e.target.value) || 25})}/><input placeholder="request timeout seconds" value={opts.nuclei_timeout} onChange={e => setOpts({...opts, nuclei_timeout: Number(e.target.value) || 4})}/><input placeholder="retries" value={opts.nuclei_retries} onChange={e => setOpts({...opts, nuclei_retries: Number(e.target.value) || 0})}/><input placeholder="stage timeout seconds" value={opts.nuclei_stage_timeout} onChange={e => setOpts({...opts, nuclei_stage_timeout: Number(e.target.value) || 300})}/><input placeholder="max URLs for full scans" value={opts.nuclei_max_urls} onChange={e => setOpts({...opts, nuclei_max_urls: Number(e.target.value) || 25})}/><p className="hint">Default full scans keep Nuclei off. Select rows in Live Hosts, Content Paths, JS Intel, Parameters, or Arjun and run focused Nuclei when needed.</p></div></SidebarGroup>
    <SidebarGroup title="JS Intel"><div className="option-stack always-on"><span className="setting-label">JavaScript + TruffleHog</span><Badge tone="ok">Always on</Badge><input placeholder="max live hosts" value={opts.js_intel_max_hosts} onChange={e => setOpts({...opts, js_intel_max_hosts: Number(e.target.value) || 80})}/><input placeholder="max scripts per host" value={opts.js_intel_max_scripts_per_host} onChange={e => setOpts({...opts, js_intel_max_scripts_per_host: Number(e.target.value) || 25})}/><input placeholder="max bytes per file" value={opts.js_intel_max_bytes} onChange={e => setOpts({...opts, js_intel_max_bytes: Number(e.target.value) || 2000000})}/><input placeholder="stage timeout seconds" value={opts.js_intel_timeout} onChange={e => setOpts({...opts, js_intel_timeout: Number(e.target.value) || 180})}/><input placeholder="TruffleHog results verified,unknown,unverified" value={opts.trufflehog_results} onChange={e => setOpts({...opts, trufflehog_results: e.target.value || 'verified,unknown,unverified'})}/><input placeholder="TruffleHog concurrency" value={opts.trufflehog_concurrency} onChange={e => setOpts({...opts, trufflehog_concurrency: Number(e.target.value) || 4})}/><p className="hint">Always downloads/analyzes JS bundles, then runs TruffleHog filesystem secret scanning on those bundles.</p></div></SidebarGroup>
    <SidebarGroup title="Parameter Discovery"><label><input type="checkbox" checked={opts.run_parameters} onChange={e => setOpts({...opts, run_parameters: e.target.checked})}/> Run gau + Katana parameter discovery</label><input placeholder="katana depth" value={opts.katana_depth} onChange={e => setOpts({...opts, katana_depth: Number(e.target.value) || 2})}/><input placeholder="katana crawl duration (2m)" value={opts.katana_crawl_duration} onChange={e => setOpts({...opts, katana_crawl_duration: e.target.value || '2m'})}/><input placeholder="parameter timeout seconds" value={opts.parameter_timeout} onChange={e => setOpts({...opts, parameter_timeout: Number(e.target.value) || 240})}/><input placeholder="max Katana URLs" value={opts.max_katana_urls || ''} onChange={e => setOpts({...opts, max_katana_urls: e.target.value ? Number(e.target.value) : null})}/><input placeholder="compact Katana raw above MB" value={opts.max_katana_output_mb} onChange={e => setOpts({...opts, max_katana_output_mb: Number(e.target.value) || 250})}/><label><input type="checkbox" checked={opts.run_katana_headless} onChange={e => setOpts({...opts, run_katana_headless: e.target.checked})}/> Katana headless crawl</label><p className="hint">Streams parameter parsing line by line and compacts oversized Katana raw logs after import.</p></SidebarGroup>
    <SidebarGroup title="Screenshots & Recovery"><label><input type="checkbox" checked={opts.run_screenshots} onChange={e => setOpts({...opts, run_screenshots: e.target.checked})}/> Run Gowitness screenshots</label><input placeholder="max screenshot URLs (blank = all)" value={opts.max_screenshot_urls || ''} onChange={e => setOpts({...opts, max_screenshot_urls: e.target.value ? Number(e.target.value) : null})}/><input placeholder="stale scan minutes" value={opts.stale_scan_minutes} onChange={e => setOpts({...opts, stale_scan_minutes: Number(e.target.value) || 30})}/><p className="hint">Screenshots now attempt all httpx URLs. Stale scans are marked automatically when raw output stops changing.</p></SidebarGroup>
    <SidebarGroup title="Arjun Options"><input placeholder="methods GET or GET,POST" value={opts.arjun_methods} onChange={e => setOpts({...opts, arjun_methods: e.target.value || 'GET'})}/><input placeholder="arjun total timeout seconds" value={opts.arjun_timeout} onChange={e => setOpts({...opts, arjun_timeout: Number(e.target.value) || 240})}/><input placeholder="arjun threads" value={opts.arjun_threads} onChange={e => setOpts({...opts, arjun_threads: Number(e.target.value) || 5})}/><input placeholder="arjun request timeout seconds" value={opts.arjun_request_timeout} onChange={e => setOpts({...opts, arjun_request_timeout: Number(e.target.value) || 10})}/><label><input type="checkbox" checked={opts.arjun_stable} onChange={e => setOpts({...opts, arjun_stable: e.target.checked})}/> Prefer stability over speed</label><p className="hint">Arjun is manual-only. Select URLs on the Arjun page and run it when you want hidden parameter probing.</p></SidebarGroup>
  </Drawer>;

  if (!active && !result && !scan) {
    return <><LandingPage domain={domain} setDomain={setDomain} run={run} targets={targets} loadTarget={loadTarget} runDisabled={runDisabled} runError={runError} alert={alert} openSettings={() => setSettingsDrawerOpen(true)}/>{settingsDrawer}<TargetLoadingScreen target={loadingTarget}/></>;
  }

  return <><div className="app-shell">
    <Header domain={domain} setDomain={setDomain} run={run} stopScan={stopScan} result={result} targets={targets} loadTarget={loadTarget} runDisabled={runDisabled} runError={runError} openTargets={() => setTargetDrawerOpen(true)} openSettings={() => setSettingsDrawerOpen(true)}/>{alert && <div className="alert">{alert}</div>}
    <main className="layout">
    <section className="workspace"><SummaryCards result={result}/><ProgressPanel scan={scanStatus} result={result}/><div className="tabs">{TABS.map(t => <button className={tab === t ? 'sel' : ''} onClick={() => setTab(t)} key={t}>{t} <span>{t === 'Subdomains' ? subdomainRows.length : t === 'Live Hosts' ? httpRows.length : t === 'Content Paths' ? dirRows.length : t === 'Vulnerabilities' ? nucleiRows.length : t === 'JS Intel' ? jsRows.length : t === 'Parameters' ? parameterRows.length : t === 'Arjun' ? arjunRows.length : t === 'Screenshots' ? (result?.screenshots || []).length : (result?.raw || []).length}</span></button>)}<div className="export-buttons"><button onClick={() => active && window.open(`${API}/targets/${active.id}/export?format=json`, '_blank')}>Export JSON</button><button onClick={() => active && window.open(`${API}/targets/${active.id}/export?format=csv`, '_blank')}>Export CSV</button></div></div>
      {showNucleiAction && <div className="bulkbar action-strip focused-run-card"><span>{selectedNucleiRows.length} selected URL{selectedNucleiRows.length === 1 ? '' : 's'} ready for focused Nuclei</span><button className="primary" disabled={!selectedNucleiRows.length || scanRunning} onClick={() => runNucleiOnRows(selectedNucleiRows)}>Run Nuclei on selected</button><span className="muted">Uses safe excludes and stores findings under Vulnerabilities with raw output.</span></div>}
      {tab === 'Subdomains' && <AssetTable rows={subdomainRows} kind="subdomains" selectRow={setDetail} selectedIds={selectedIds} toggleSelected={toggleSelected} markInteresting={markInteresting}/>}
      {tab === 'Live Hosts' && <><h3>200 OK</h3><AssetTable rows={http200} kind="http" selectRow={setDetail} selectedIds={selectedIds} toggleSelected={toggleSelected} markInteresting={markInteresting} runNucleiOnRows={runNucleiOnRows}/><h3>Other Status Codes</h3><AssetTable rows={httpOther} kind="http" selectRow={setDetail} selectedIds={selectedIds} toggleSelected={toggleSelected} markInteresting={markInteresting} runNucleiOnRows={runNucleiOnRows}/></>}
      {tab === 'Content Paths' && <AssetTable rows={dirRows} kind="dirs" selectRow={setDetail} selectedIds={selectedIds} toggleSelected={toggleSelected} markInteresting={markInteresting} runNucleiOnRows={runNucleiOnRows}/>}
      {tab === 'Vulnerabilities' && <AssetTable rows={nucleiRows} kind="nuclei_findings" selectRow={setDetail} selectedIds={selectedIds} toggleSelected={toggleSelected} markInteresting={markInteresting}/>}
      {tab === 'JS Intel' && <AssetTable rows={jsRows} kind="js_findings" selectRow={setDetail} selectedIds={selectedIds} toggleSelected={toggleSelected} markInteresting={markInteresting} runNucleiOnRows={runNucleiOnRows}/>}
      {tab === 'Parameters' && <AssetTable rows={parameterRows} kind="parameters" selectRow={setDetail} selectedIds={selectedIds} toggleSelected={toggleSelected} markInteresting={markInteresting} runNucleiOnRows={runNucleiOnRows}/>}
      {tab === 'Arjun' && <><div className="bulkbar action-strip"><span>{selectedParameterUrls.length} selected URL{selectedParameterUrls.length === 1 ? '' : 's'} ready for Arjun</span><button className="primary" disabled={!selectedParameterUrls.length || scanRunning} onClick={runArjunOnSelectedParameters}>Run Arjun on selected URLs</button><span className="muted">Select candidate URLs below; results appear in the Arjun Results table.</span></div><h3>Candidate URLs from Parameter Discovery</h3><AssetTable rows={parameterRows} kind="parameters" selectRow={setDetail} selectedIds={selectedIds} toggleSelected={toggleSelected} markInteresting={markInteresting} runNucleiOnRows={runNucleiOnRows}/><h3>Arjun Results</h3><AssetTable rows={arjunRows} kind="parameters" selectRow={setDetail} selectedIds={selectedIds} toggleSelected={toggleSelected} markInteresting={markInteresting} runNucleiOnRows={runNucleiOnRows}/></>}
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

createRoot(document.getElementById('root')).render(window.location.pathname === '/logs' ? <LogsPage/> : window.location.pathname === '/playground' ? <PlaygroundPage/> : window.location.pathname === '/security-lab' ? <SecurityLabPage/> : <App/>);
