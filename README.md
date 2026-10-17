# verify-dont-trust

**A leak scanner for things that were never meant to ship.** Zero dependencies, one file, exit code 1 when it finds something — so it drops straight into CI.

```bash
node verify.mjs --dir ./public
```

## Why this exists

Every project has a "before you publish" checklist. Every checklist gets skipped exactly once — the late night, the final deploy, the twenty minutes before an interview.

And the things that leak are rarely dramatic:

- the client's **old brand name**, still sitting in a `<title>` three files away
- an **absolute path** from the machine that built it (`C:\Users\you\client-project\`) — which tells a stranger your username and your folder layout
- a **test key** left in a config
- a **`TODO: replace before launch`** that nobody replaced
- a **`.pem`** in the folder, which a text-only scanner will happily approve

**None of those throw an error. All of them are visible to a stranger in one click.** The last one is the reason this tool checks file *names* as well as contents: the first version of it scanned only text, and its own self-test caught it missing a private key file. That is the argument for shipping a self-test with a scanner.

## What it checks

| rule | catches |
|---|---|
| `private-key` | `-----BEGIN … PRIVATE KEY-----` blocks pasted into text |
| `key-file` | `.pem` `.key` `.p12` `.pfx` `.jks` files in the folder |
| `ssh-key` | `id_rsa`, `id_ed25519`, and friends |
| `dotenv` | `.env` files |
| `credentials-file` | `credentials`, `secrets`, `.npmrc`, `.netrc`, service-account JSON |
| `aws-access-key` · `github-token` · `slack-token` · `stripe-key` · `google-api-key` · `openai-style-key` | credential-shaped strings |
| `absolute-windows-path` · `absolute-home-path` · `file-url` | paths from a builder's machine |
| `term` | **anything you list in your config** — old brands, client names, internal hostnames |
| `todo` · `replace-me` · `placeholder-word` · `lorem` | unfinished text in HTML/CSS about to be published |

Secret-shaped matches are **redacted** in the report, so a finding can be pasted into an issue without leaking the very thing it caught.

## Configuration

```bash
node verify.mjs --example-config > .leakscan.json
```

```json
{
  "terms": [
    { "value": "oldbrandname.com", "why": "the domain we moved off" },
    { "value": "Acme Holdings LLC", "why": "must not appear on a public page" }
  ],
  "placeholders": true,
  "ignore": ["CHANGELOG.md", "fixtures/**", "*.txt"]
}
```

- **`terms`** — plain strings, matched case-insensitively. Add `"regex": true` for a pattern, `"caseSensitive": true` if you must.
- **`placeholders`** — the TODO/placeholder pass, applied to HTML and CSS only (it would be noise in code).
- **`ignore`** — globs, relative to the scanned folder. `*` within a path segment, `**` across them.

## Also scans a URL

```bash
node verify.mjs --url https://example.com
```

Same rules, applied to the bytes a server actually hands out — which is not always the same as the file you edited.

## Machine-readable output for CI

```bash
node verify.mjs --dir ./public --json > report.json
# exit 1 means findings; fail the build on it
```

## Self-test

```bash
node verify.mjs --self-test
```

Builds a clean fixture and a dirty one in a temp directory and asserts every rule fires, that findings carry line numbers, that secrets are redacted, and that ignore globs work. **A checker you have never seen fail is a checker you cannot trust** — so this one proves itself before it is trusted with anything.

## Scope, honestly

It is a **text scanner**, not a secret detector with entropy analysis. It will not find a secret that looks like an ordinary string. It cannot see inside images, PDFs, `node_modules`, or a git history — `git log -p | grep` is still your friend for the last one.

What it does is catch the four classes of mistake that actually reach a public folder, cheaply, in under a second, without a network call unless you ask for one.

## License

MIT — see [LICENSE](LICENSE).
