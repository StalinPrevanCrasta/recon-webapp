import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';

const src = readFileSync(new URL('../src/main.jsx', import.meta.url), 'utf8');

assert.match(src, /View Logs/, 'header includes View Logs label');
assert.match(src, /window\.open\('\/logs', '_blank', 'noopener,noreferrer'\)/, 'View Logs opens /logs in a safe new tab');
assert.match(src, /function LogsPage\(/, 'dedicated LogsPage exists');
assert.match(src, /new EventSource\(`\$\{API\}\/system\/logs\/stream/, 'logs page connects to SSE endpoint');
assert.match(src, /All containers/, 'logs page has all containers option');
assert.match(src, /Pause/, 'logs page has pause control');
assert.match(src, /Auto-scroll/, 'logs page has auto-scroll control');
assert.match(src, /Copy visible logs/, 'logs page has copy control');
assert.match(src, /Download/, 'logs page has download control');
assert.match(src, /slice\(-bufferLimit\)/, 'maximum frontend buffer is enforced');
assert.match(src, /highlight\(/, 'search highlighting is wired');
assert.doesNotMatch(src, /dangerouslySetInnerHTML/, 'logs are not rendered with dangerouslySetInnerHTML');
assert.match(src, /function TargetLoadingScreen\(/, 'target loading screen exists');
assert.match(src, /setLoadingTarget\(t\)[\s\S]*targets\/\$\{t\.id\}\/results/, 'target results load only after the loading state is shown');
assert.match(src, /Other targets remain unloaded/, 'loading screen explains lazy target loading');

console.log('frontend log viewer static tests passed');
