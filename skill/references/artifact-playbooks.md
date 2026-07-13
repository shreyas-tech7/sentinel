# SENTINEL Artifact Playbooks

For artifact types where **"route handler" is the wrong entry-point model.** A web app's entry points
are its routes; a browser extension's are its message listeners and content-script injection points, a
bot's are its commands and webhook, a CLI tool's are its arguments and the files it reads. Phase 0's
artifact classification decides which of these you're auditing; this file gives the entry-point map,
top traps, and test method for each.

The classic catalog classes (A–H) **still apply** — a bot's backend has IDOR and injection like any
other, a CLI's config parser has the same deserialization sink as a web server. What changes is *where
the untrusted input enters* and *what the trust boundary is*. These playbooks cover the platform-boundary
classes ([SENT-PLAT-01](vulnerability-catalog.md#sent-plat-01--overscoped-platform-permissions-and-privileges),
[SENT-PLAT-02](vulnerability-catalog.md#sent-plat-02--unvalidated-cross-context-messages)) that only
exist here, and point back to the shared classes for the rest.

Mobile apps are a **stack**, not an artifact-boundary special case — their playbook lives at
[`stack-playbooks/mobile.md`](stack-playbooks/mobile.md). Don't duplicate it here.

---

## Browser extensions

### Entry-point map
Not routes — **four** channels, each an untrusted boundary: (1) the pages a content script is injected
into (fully attacker-controlled DOM and `postMessage`), (2) messages between content script and
background/service worker, (3) `externally_connectable` messages from web pages, (4) the extension's own
options/popup UI. The `manifest.json` permission set defines the blast radius of a bug on any of them.

### Top traps
1. **Overscoped `manifest.json` permissions.** `<all_urls>` host access and broad APIs (`tabs`,
   `cookies`, `webRequest`) for a single-site feature — every one is inherited by any injection or
   message-handling bug. → [SENT-PLAT-01](vulnerability-catalog.md#sent-plat-01--overscoped-platform-permissions-and-privileges)
2. **Content script trusting `window.postMessage` from the page.** The page the script runs in is
   hostile; a handler that acts on `event.data` without an `event.origin` allow-list lets any site drive
   the extension's privileges. → [SENT-PLAT-02](vulnerability-catalog.md#sent-plat-02--unvalidated-cross-context-messages)
3. **Background message handler with no `sender` validation.** `chrome.runtime.onMessage` /
   `onMessageExternal` doing privileged work (cookie reads, cross-origin fetch with extension host
   permissions) without checking `sender.id` / `sender.origin`. →
   [SENT-PLAT-02](vulnerability-catalog.md#sent-plat-02--unvalidated-cross-context-messages)
4. **Secrets in `chrome.storage` unencrypted.** API keys or tokens in `chrome.storage.local` — readable
   by anyone with filesystem/devtools access to the profile; and any key bundled in the extension source
   is public (the package is unpacked trivially). →
   [SENT-SECRET-01](vulnerability-catalog.md#sent-secret-01--hard-coded-or-client-exposed-secrets)
5. **Injecting page-derived data as HTML** into the extension UI or back into the page —
   `innerHTML = message.text`. → [SENT-INJ-02](vulnerability-catalog.md#sent-inj-02--cross-site-scripting-xss)
6. **Remotely hosted code / `eval`** in an extension context — forbidden by MV3 for exactly this reason;
   flag any `eval`, `new Function`, or remote `<script>` in extension pages.

### How to test
- Read `manifest.json` first: list every permission and host, and demand a feature that uses each. Everything
  unexplained is a [SENT-PLAT-01](vulnerability-catalog.md#sent-plat-01--overscoped-platform-permissions-and-privileges) finding.
- From a test page the content script matches, `postMessage` a crafted payload and confirm the handler
  ignores it (origin check) rather than acting.
- Grep the background/worker for `onMessage`/`onMessageExternal` and confirm each privileged branch gates
  on `sender`.
- Unpack the built extension (it's a zip) and grep for key shapes; anything found is leaked.

---

## Chat bots (Discord / Slack / Telegram)

### Entry-point map
Two boundaries: (1) **commands / messages** from any user in any server or DM the bot is in — the
username, arguments, and message content are all attacker-controlled; (2) the **interactions webhook**
(Slack, Discord HTTP interactions), an HTTP endpoint anyone can POST to. The bot token is the crown
jewel: it *is* the bot. There is no per-object ownership model handed to you — you build authorization
out of the platform's role/permission data, server-side, on every privileged command.

### Top traps
1. **Privileged commands gated by UI visibility, not a role check.** `ban`, `kick`, `config`, `payout`
   hidden from the command list or the help text but still invokable by any user who types them, because
   the handler never verifies the caller's server role/permission on the server side. Hiding a command is
   not gating it. → [SENT-AUTHZ-02](vulnerability-catalog.md#sent-authz-02--broken-function-level-authorization)
2. **Bot token committed or logged.** The token in the repo, in a `.env` that's committed, or printed by
   a debug `console.log(config)`. A leaked token is full bot takeover. →
   [SENT-SECRET-01](vulnerability-catalog.md#sent-secret-01--hard-coded-or-client-exposed-secrets),
   [SENT-LOG-02](vulnerability-catalog.md#sent-log-02--secrets-and-pii-written-to-logs-and-telemetry)
3. **User input into `eval` / shell / a template.** A `!calc` or `!run` command passing the argument to
   `eval()`, a shell, or a template engine — code execution from a chat message. →
   [SENT-INJ-01](vulnerability-catalog.md#sent-inj-01--injection-sql--command--code--template)
4. **Webhook signature skipped or checked against the wrong secret.** The interactions endpoint acting on
   unsigned POSTs (Slack's `X-Slack-Signature`, Discord's Ed25519 header), or verifying against a
   mismatched secret — anyone forges interactions. →
   [SENT-SECRET-04](vulnerability-catalog.md#sent-secret-04--unverified-webhook-payloads)
5. **Overscoped bot invite / intents.** Administrator permission (`permissions=8`) or every gateway
   intent, when the commands need a handful. →
   [SENT-PLAT-01](vulnerability-catalog.md#sent-plat-01--overscoped-platform-permissions-and-privileges)
6. **No per-user rate limit on an expensive command** (an LLM call, an image render) — denial-of-wallet
   from a single user spamming it. → [SENT-INJ-05](vulnerability-catalog.md#sent-inj-05--missing-rate-limits-on-heavy-or-metered-operations)

### How to test
- For every privileged command, invoke it as an unprivileged member and confirm a server-side denial —
  not just that the button/command was hidden.
- POST a forged (unsigned, or wrong-secret) payload to the interactions webhook and confirm rejection.
- Grep for the token in source and history; grep command handlers for `eval`, `exec`, `child_process`,
  shell calls, and template rendering of user args.
- Check the invite URL's permission integer and the enabled intents against the actual command set.

---

## CLI tools

### Entry-point map
The untrusted inputs are (1) **arguments and flags**, (2) **environment variables**, (3) **the files the
tool reads** — config, project manifests, data files — and (4) **stdin**. "It's a local tool, the user
is trusted" is false the moment the tool runs in CI, processes a downloaded project, reads a config from
a cloned repo, or runs with elevated privilege. The config file from an untrusted repo is exactly as
hostile as an HTTP request body.

### Top traps
1. **Argument / flag injection into a subprocess.** Building a shell command by interpolating a
   user-supplied value (`os.system(f"git clone {url}")`), or passing user input as a flag that the
   subprocess interprets (`--upload-pack`, `-o ProxyCommand`). Use an argv array and `--` to terminate
   option parsing. → [SENT-INJ-01](vulnerability-catalog.md#sent-inj-01--injection-sql--command--code--template)
2. **Unsafe path handling.** A `--output` / `--dest` / archive-entry path with `../` or an absolute path
   escaping the intended directory — write-anywhere, which is privilege escalation if the tool runs with
   more rights than the invoker. → [SENT-INJ-10](vulnerability-catalog.md#sent-inj-10--path-traversal-and-unsafe-file-path-handling)
3. **Unsafe deserialization of config.** `yaml.load` (not `safe_load`), `pickle`, or `Marshal.load` on a
   config or data file the tool reads — code execution from a file the tool was merely pointed at. →
   [SENT-INJ-09](vulnerability-catalog.md#sent-inj-09--unsafe-deserialization-of-untrusted-data)
4. **Privilege-escalation patterns.** A tool that expects `sudo`/administrator for its whole run when one
   operation needs it; a setuid helper; writing to a world-writable path that a privileged process later
   executes. → [SENT-PLAT-01](vulnerability-catalog.md#sent-plat-01--overscoped-platform-permissions-and-privileges)
5. **Secrets echoed or logged.** Printing the full config (including tokens) on `--verbose`, or writing
   credentials to a world-readable log/cache file. →
   [SENT-LOG-02](vulnerability-catalog.md#sent-log-02--secrets-and-pii-written-to-logs-and-telemetry)
6. **Auto-updater / plugin loader with no integrity check** — fetching and executing code with no
   signature verification. → [SENT-SUPPLY-01](vulnerability-catalog.md#sent-supply-01--unpinned-or-unmaintained-dependencies)

### How to test
- Run every subcommand with a value containing shell metacharacters (`; id`, `$(id)`, backticks) and a
  path containing `../`; confirm neither escapes.
- Point the tool at a config file containing a deserialization payload and confirm it doesn't execute.
- Run with `--verbose`/`--debug` and confirm no secret reaches stdout or a log file.
- Check whether the documented run command needs elevation, and whether the code actually requires it or
  just assumes it.

---

## Desktop apps (Electron and native)

### Entry-point map
For Electron specifically, the boundary is **renderer → main process IPC**: the renderer may load or
render remote/attacker-influenced content, and every `ipcMain` channel is an entry point into the
privileged Node context. Native desktop apps add **custom URL-scheme handlers**, **file associations**,
and **local IPC / named pipes** as entry points — each an untrusted input if another local process or a
web page can reach it.

### Top traps
1. **`nodeIntegration: true` / `contextIsolation: false`** on a window that renders any remote or
   user-supplied content — an XSS in that content becomes full OS-level code execution. Keep
   `contextIsolation: true` and expose narrow functions via `contextBridge`. →
   [SENT-PLAT-02](vulnerability-catalog.md#sent-plat-02--unvalidated-cross-context-messages)
2. **Over-broad IPC handlers.** `ipcMain.handle('readFile', (e, p) => fs.readFile(p))` — the renderer
   passes any path; a compromised renderer reads the whole filesystem. Validate and scope every IPC
   argument as attacker-controlled. → [SENT-PLAT-02](vulnerability-catalog.md#sent-plat-02--unvalidated-cross-context-messages),
   [SENT-INJ-10](vulnerability-catalog.md#sent-inj-10--path-traversal-and-unsafe-file-path-handling)
3. **Custom URL scheme / deep link executing actions** without validating the URI — another app or a web
   link invokes `myapp://` with attacker parameters. →
   [SENT-PLAT-02](vulnerability-catalog.md#sent-plat-02--unvalidated-cross-context-messages)
4. **Loading remote content into a privileged window**, or disabling web security
   (`webSecurity: false`). → [SENT-SECRET-02](vulnerability-catalog.md#sent-secret-02--permissive-cors-missing-headers-debug-mode)
5. **Secrets bundled in the app.** An Electron/desktop bundle is unpackable (`asar` is not encryption);
   any embedded key is public. → [SENT-SECRET-01](vulnerability-catalog.md#sent-secret-01--hard-coded-or-client-exposed-secrets)

### How to test
- Read the `BrowserWindow` `webPreferences`: confirm `contextIsolation: true`, `nodeIntegration: false`,
  `sandbox: true`, and no `webSecurity: false`.
- Enumerate every `ipcMain.handle`/`on` channel and confirm each validates its arguments and scopes file
  and shell access.
- Fire the app's custom scheme with crafted parameters and confirm no sensitive action runs unvalidated.
- Unpack the `asar`/bundle and grep for secrets.

---

## Adding an artifact playbook

Same shape as a stack playbook, but lead with the **entry-point map** — the whole reason a type lands
here is that its entry points aren't routes. Cross-link every trap to a catalog ID, and if the type
needs a boundary class the catalog doesn't have yet, add it under
[Platform & artifact boundaries](vulnerability-catalog.md#platform--artifact-boundaries) first. See
[CONTRIBUTING.md](../../CONTRIBUTING.md).
