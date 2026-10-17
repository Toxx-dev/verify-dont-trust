#!/usr/bin/env node
// verify-dont-trust — a leak scanner for things that were never meant to ship.
//
// WHY IT EXISTS. Every site has a "before you publish" checklist, and every checklist gets skipped
// exactly once: the late night, the final deploy, the twenty minutes before an interview. The things
// that leak are rarely dramatic. They are the client's old brand name still sitting in a title tag,
// an absolute path from the machine that built it, a test API key in a config, a `TODO: replace
// before launch` that nobody replaced.
//
// None of those throw an error. All of them are visible to a stranger in one click.
//
// This scans a folder (or a URL you already decided is public) for four classes of that mistake:
//
//   1. TERMS      words you say must never appear in shipped text (old brand, private names, hostnames)
//   2. PATHS      absolute filesystem paths from a builder's machine  (C:\Users\..., /home/...)
//   3. SECRETS    credential-shaped strings (private keys, cloud keys, common token prefixes)
//   4. PLACEHOLDERS  TODO/FIXME/"replace me" markers in files that are about to be published
//
// DEPENDENCIES: none. Node 18+. Exit code 1 on any finding, so it drops straight into CI.
//
// USAGE
//   node verify.mjs --dir ./public
//   node verify.mjs --dir ./public --config .leakscan.json
//   node verify.mjs --url https://example.com
//   node verify.mjs --self-test
//
// EXIT CODES
//   0  clean
//   1  findings (each one printed with file, line and why)
//   2  usage or configuration error

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

const VERSION = '1.0.0';

// ---------------------------------------------------------------------------------------------
// Text we can honestly scan. Anything else is media or binary, and guessing about binaries produces
// noise, which is how a checker ends up switched off.
// ---------------------------------------------------------------------------------------------
const TEXT_EXT = new Set([
  '.html', '.htm', '.css', '.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx', '.json', '.md', '.txt',
  '.svg', '.xml', '.yml', '.yaml', '.toml', '.ini', '.cfg', '.env', '.sh', '.ps1', '.py', '.sql',
]);

// File NAMES that have no business being in a folder you are about to publish. This is checked
// before the text scan, and against every file - not just text ones. A `.pem` is not readable text,
// and a scanner that only looks at text will happily approve a folder containing a private key.
// (That failure was caught by this tool's own self-test on the first run, which is the point of
// having one.)
const SECRET_FILES = [
  { id: 'key-file', why: 'a private key / certificate file in a publish folder', re: /\.(pem|key|p12|pfx|jks|keystore)$/i },
  { id: 'ssh-key', why: 'an SSH private key in a publish folder', re: /^id_(rsa|dsa|ecdsa|ed25519)(\.pub)?$/i },
  { id: 'dotenv', why: 'a .env file in a publish folder — it exists to hold secrets', re: /^\.env(\..+)?$/i },
  { id: 'credentials-file', why: 'a credentials file in a publish folder', re: /^(credentials|secrets|\.npmrc|\.netrc|service[-_]?account.*\.json)$/i },
];

const SKIP_DIRS = new Set(['.git', 'node_modules', 'venv', '.venv', '__pycache__', '.next', 'dist']);

// ---------------------------------------------------------------------------------------------
// Built-in rules. These are the classes that are wrong regardless of which folder you are in, so
// they are on by default and cannot be forgotten.
// ---------------------------------------------------------------------------------------------
const BUILTIN = [
  {
    id: 'private-key',
    why: 'a private key block — never ship one, and never commit one',
    re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  },
  {
    id: 'aws-access-key',
    why: 'AWS access key id',
    re: /\bAKIA[0-9A-Z]{16}\b/,
  },
  {
    id: 'github-token',
    why: 'GitHub token',
    re: /\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b/,
  },
  {
    id: 'slack-token',
    why: 'Slack token',
    re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/,
  },
  {
    id: 'stripe-key',
    why: 'Stripe secret key',
    re: /\bsk_live_[A-Za-z0-9]{10,}\b/,
  },
  {
    id: 'google-api-key',
    why: 'Google API key',
    re: /\bAIza[0-9A-Za-z_-]{30,}\b/,
  },
  {
    id: 'openai-style-key',
    why: 'API key in sk- form',
    re: /\bsk-[A-Za-z0-9]{20,}\b/,
  },
  {
    id: 'absolute-windows-path',
    why: 'an absolute path from the machine that built this — it tells a stranger your username and folder layout',
    re: /\b[A-Za-z]:\\(?:Users|Documents|Desktop|Dropbox|Projects|src|dev|work)\\[^\s"'<>)]+/,
  },
  {
    id: 'absolute-home-path',
    why: 'an absolute path from a builder\'s home directory',
    // /Users/someone/... or /home/someone/... but not /home (a plain web path)
    re: /(?<![\w.-])\/(?:Users|home)\/[A-Za-z0-9._-]+\/[^\s"'<>)]*/,
  },
  {
    id: 'file-url',
    why: 'a file:// URL — a local path wearing a protocol',
    re: /\bfile:\/\/\/[^\s"'<>)]+/,
  },
];

// Placeholder markers. Only reported when the file looks like something that is about to ship.
const PLACEHOLDER = [
  { id: 'todo', why: 'a TODO marker in a publishable file', re: /\b(TODO|FIXME|XXX)\b/ },
  { id: 'replace-me', why: 'an explicit "replace before launch" marker', re: /replace\s+(?:this|me|before)\b/i },
  { id: 'placeholder-word', why: 'the word "placeholder" in shipped text', re: /\bplaceholder\b/i },
  { id: 'lorem', why: 'lorem ipsum filler', re: /\blorem ipsum\b/i },
];

// ---------------------------------------------------------------------------------------------
// Configuration: a JSON file of terms you never want to see again.
// ---------------------------------------------------------------------------------------------
const EXAMPLE_CONFIG = {
  note: 'Copy to .leakscan.json and edit. Every entry is scanned case-insensitively unless you say otherwise.',
  terms: [
    { value: 'oldbrandname.com', why: 'the domain we moved off' },
    { value: 'Acme Holdings LLC', why: 'the client name that must not appear on a public page' },
  ],
  // Turned off by default when you pass --dir with a docs tree, on by default otherwise.
  placeholders: true,
  ignore: ['CHANGELOG.md', 'test/fixtures/**'],
};

function loadConfig(file) {
  if (!file) return { terms: [], placeholders: true, ignore: [] };
  const raw = fs.readFileSync(file, 'utf8');
  const cfg = JSON.parse(raw);
  return {
    terms: Array.isArray(cfg.terms) ? cfg.terms : [],
    placeholders: cfg.placeholders !== false,
    ignore: Array.isArray(cfg.ignore) ? cfg.ignore : [],
  };
}

/** Minimal glob: supports ** and * only, which is all a config file needs. */
function globToRe(glob) {
  const escaped = glob
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*\*/g, '\u0000')
    .replace(/\*/g, '[^/]*')
    .replace(/\u0000/g, '.*');
  return new RegExp('^' + escaped + '$');
}

const isIgnored = (rel, ignore) => ignore.some((g) => globToRe(g).test(rel.replace(/\\/g, '/')));

// ---------------------------------------------------------------------------------------------
// Walking
// ---------------------------------------------------------------------------------------------
function* walk(dir, root = dir) {
  let ents;
  try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
  for (const e of ents) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (SKIP_DIRS.has(e.name)) continue;
      yield* walk(full, root);
      continue;
    }
    // Every file is yielded (so name-based rules see them); text scanning is decided by the caller.
    yield { file: full, rel: path.relative(root, full), isText: TEXT_EXT.has(path.extname(e.name).toLowerCase()) };
  }
}

// ---------------------------------------------------------------------------------------------
// Scanning
// ---------------------------------------------------------------------------------------------
function rulesFor(cfg, rel) {
  const rules = [...BUILTIN];
  for (const t of cfg.terms) {
    if (!t || typeof t.value !== 'string' || !t.value) continue;
    const body = t.regex ? t.value : t.value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    rules.push({
      id: 'term',
      why: t.why || `a term you listed as must-not-ship: ${t.value}`,
      re: new RegExp(body, t.caseSensitive ? 'g' : 'gi'),
    });
  }
  const publishing = /\.(html?|css)$/i.test(rel) || rel === 'index.html';
  if (cfg.placeholders && publishing) rules.push(...PLACEHOLDER);
  return rules;
}

/** Hide enough of a match that the report can be pasted into an issue. */
function redact(text) {
  if (text.length <= 12) return text.replace(/.(?=.{2})/g, '*');
  return text.slice(0, 4) + '*'.repeat(Math.min(12, text.length - 8)) + text.slice(-4);
}

function scanText(text, rules, label) {
  const findings = [];
  const lines = text.split(/\r?\n/);
  for (const rule of rules) {
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (!line) continue;
      // a global regex carries lastIndex between calls; reset before each test
      rule.re.lastIndex = 0;
      const m = rule.re.exec(line);
      if (!m) continue;
      const secretish = /key|token|secret/.test(rule.id);
      findings.push({
        where: label,
        line: i + 1,
        rule: rule.id,
        why: rule.why,
        match: secretish ? redact(m[0]) : m[0].slice(0, 120),
      });
    }
  }
  return findings;
}

async function scanDir(dir, cfg) {
  const findings = [];
  const scanned = [];
  const skipped = [];
  for (const entry of walk(dir)) {
    const rel = entry.rel.replace(/\\/g, '/');
    if (isIgnored(rel, cfg.ignore)) { skipped.push(rel); continue; }

    // 1. the name itself, for every file — a secret file is a finding even if it is binary
    const base = path.basename(rel);
    for (const rule of SECRET_FILES) {
      rule.re.lastIndex = 0;
      if (rule.re.test(base)) {
        findings.push({ where: rel, line: 1, rule: rule.id, why: rule.why, match: base });
      }
    }

    // 2. and the contents, for text files
    if (!entry.isText) { continue; }
    let text;
    try { text = fs.readFileSync(entry.file, 'utf8'); } catch { skipped.push(rel); continue; }
    scanned.push(rel);
    findings.push(...scanText(text, rulesFor(cfg, rel), rel));
  }
  return { findings, scanned, skipped };
}

async function scanUrl(url, cfg) {
  const res = await fetch(url, { redirect: 'follow' });
  if (!res.ok) throw new Error(`GET ${url} -> ${res.status}`);
  const body = await res.text();
  return { findings: scanText(body, rulesFor(cfg, new URL(url).pathname || '/'), url), scanned: [url], skipped: [] };
}

// ---------------------------------------------------------------------------------------------
// Self-test: the tool proves itself against fixtures instead of being trusted.
// ---------------------------------------------------------------------------------------------
async function selfTest() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'leakscan-'));
  const results = [];
  const check = (name, ok, detail = '') => { results.push({ name, ok }); console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? '  — ' + detail : ''}`); };
  try {
    fs.mkdirSync(path.join(dir, 'clean'), { recursive: true });
    fs.mkdirSync(path.join(dir, 'dirty'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'clean', 'index.html'), '<!doctype html><title>Hello</title><p>Nothing to hide here.</p>');
    fs.writeFileSync(path.join(dir, 'clean', 'app.css'), 'body { color: #111; }');
    fs.writeFileSync(path.join(dir, 'dirty', 'index.html'),
      '<title>Hello</title>\n<!-- TODO: replace this before launch -->\n<p>Path: C:\\Users\\someone\\secret-project\\notes.md</p>\n');
    fs.writeFileSync(path.join(dir, 'dirty', 'config.js'), 'const k = "sk_live_abcdefghijklmnop";\n');
    fs.writeFileSync(path.join(dir, 'dirty', 'key.pem'), '-----BEGIN RSA PRIVATE KEY-----\nzzz\n-----END RSA PRIVATE KEY-----\n');
    // a PEM block pasted into a TEXT file, so the content rule is tested separately from the
    // name rule: both must fire, and for different reasons
    fs.writeFileSync(path.join(dir, 'dirty', 'notes.txt'), 'here is a key I pasted by mistake:\n-----BEGIN OPENSSH PRIVATE KEY-----\nzzz\n-----END OPENSSH PRIVATE KEY-----\n');

    const cfg = { terms: [{ value: 'acme-internal', why: 'the old brand' }], placeholders: true, ignore: [] };
    fs.writeFileSync(path.join(dir, 'dirty', 'page.html'), '<title>acme-internal portal</title>');

    const clean = await scanDir(path.join(dir, 'clean'), cfg);
    check('a clean folder reports nothing', clean.findings.length === 0, `${clean.findings.length} findings`);

    const dirty = await scanDir(path.join(dir, 'dirty'), cfg);
    const ids = dirty.findings.map((f) => f.rule);
    check('a Windows path is caught', ids.includes('absolute-windows-path'));
    check('a key FILE in the folder is caught by name', ids.includes('key-file'));
    check('a private key pasted into text is caught by content', ids.includes('private-key'));
    check('a live secret is caught', ids.includes('stripe-key'));
    check('a configured term is caught', ids.includes('term'));
    check('a TODO in html is caught', ids.includes('todo'));
    check('secrets are redacted in the report', dirty.findings.filter((f) => f.rule === 'stripe-key').every((f) => f.match.includes('*')));
    check('every finding carries a line number', dirty.findings.every((f) => Number.isInteger(f.line) && f.line > 0));

    const ignored = await scanDir(path.join(dir, 'dirty'), { ...cfg, ignore: ['config.js', 'key.pem', 'index.html', 'page.html', '*.txt'] });
    check('ignore globs (including *.txt) remove files from the scan', ignored.findings.length === 0, `${ignored.findings.length} findings`);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  const failed = results.filter((r) => !r.ok).length;
  console.log(`\n  ${results.length - failed}/${results.length} passed${failed ? ' — ' + failed + ' FAILED' : ''}`);
  return failed === 0;
}

// ---------------------------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------------------------
const argv = process.argv.slice(2);
const arg = (name, fallback = null) => {
  const i = argv.indexOf('--' + name);
  return i >= 0 && argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[i + 1] : fallback;
};

if (argv.includes('--self-test')) {
  console.log(`verify-dont-trust v${VERSION} — self-test\n`);
  const ok = await selfTest();
  process.exit(ok ? 0 : 1);
}

if (argv.includes('--example-config')) {
  console.log(JSON.stringify(EXAMPLE_CONFIG, null, 2));
  process.exit(0);
}

const dir = arg('dir');
const url = arg('url');
const configFile = arg('config');
const JSON_OUT = argv.includes('--json');

if (!dir && !url) {
  console.log(`verify-dont-trust v${VERSION} — a leak scanner for things that were never meant to ship

  node verify.mjs --dir <folder> [--config .leakscan.json]
  node verify.mjs --url <url>    [--config .leakscan.json]
  node verify.mjs --self-test
  node verify.mjs --example-config

  rules: ${BUILTIN.map((r) => r.id).join(' · ')}
         plus a "placeholders" pass over html/css when placeholders are enabled

  exit 0 clean · 1 findings · 2 usage`);
  process.exit(2);
}

let cfg;
try { cfg = loadConfig(configFile); } catch (e) {
  console.error(`config error: ${e.message}`);
  process.exit(2);
}

try {
  const result = dir ? await scanDir(path.resolve(dir), cfg) : await scanUrl(url, cfg);
  const { findings, scanned, skipped } = result;

  if (JSON_OUT) {
    console.log(JSON.stringify({
      version: VERSION,
      target: dir ? path.resolve(dir) : url,
      scanned,
      skipped,
      findings,
      clean: findings.length === 0,
    }, null, 2));
    process.exit(findings.length ? 1 : 0);
  }

  console.log(`verify-dont-trust v${VERSION}`);
  console.log(`  scanned : ${scanned.length} file(s)${skipped.length ? `  ·  skipped ${skipped.length}` : ''}`);
  if (dir) console.log(`  folder  : ${path.resolve(dir)}`);
  if (url) console.log(`  url     : ${url}`);

  if (!findings.length) {
    console.log('\n  CLEAN — nothing that was meant to stay private is in here.');
    process.exit(0);
  }

  console.log(`\n  ${findings.length} FINDING(S):`);
  for (const f of findings) {
    console.log(`\n  ${f.where}:${f.line}  [${f.rule}]`);
    console.log(`    why   : ${f.why}`);
    console.log(`    found : ${f.match}`);
  }
  console.log('\n  Fix the text, not the scanner. If a finding is a false positive, add it to `ignore`.');
  process.exit(1);
} catch (e) {
  console.error(`scan failed: ${e.message}`);
  process.exit(2);
}
