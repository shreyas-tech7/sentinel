# PHP (Laravel / WordPress)

Part of the [SENTINEL stack playbooks](../stack-playbooks.md).

## Key
Laravel, like Rails, is safe by convention and breached through the escape hatches. WordPress is a
different animal: the core is hardened, but the attack surface is the *plugins and themes* bolted on,
and the config and upload directories left reachable over HTTP.

## Trust model
- **Laravel:** the framework parameterizes Eloquent, escapes Blade (`{{ }}`), and ships CSRF middleware.
  The `.env` file holds `APP_KEY` (encrypts sessions/cookies) and every credential — it must never be
  web-reachable or committed. `$fillable`/`$guarded` on each model is the mass-assignment allow-list.
- **WordPress:** every plugin and theme runs with full application privilege; a vulnerable one is a
  vulnerable site. `wp-config.php` holds the DB credentials and secret keys. `wp-content/uploads` is
  world-readable by design.
- In both, the document root matters: if the web server serves the project root rather than a `public/`
  subdirectory, `.env`, `.git`, and config files are one URL away.

## Top traps
1. **`.env` reachable over HTTP.** Server misconfigured to serve the app root, so `GET /.env` returns
   `APP_KEY` and every credential. Also `.git/`, `composer.lock`, and `storage/logs` exposed the same
   way. → [SENT-SECRET-01](../vulnerability-catalog.md#sent-secret-01--hard-coded-or-client-exposed-secrets)
2. **Eloquent mass assignment.** `Model::create($request->all())` on a model with an unrestricted
   `$fillable` (or `$guarded = []`) — attacker sets `is_admin`, `role`, `user_id`. →
   [SENT-INJ-03](../vulnerability-catalog.md#sent-inj-03--mass-assignment--over-allocation)
3. **Raw SQL / `DB::raw` with interpolation.** `DB::select("... where email = '$email'")` or
   `whereRaw("name = '$q'")` — bypasses the query builder's binding. →
   [SENT-INJ-01](../vulnerability-catalog.md#sent-inj-01--injection-sql--command--code--template)
4. **Blade escape hatch.** `{!! $userContent !!}` renders unescaped — the Blade equivalent of
   `dangerouslySetInnerHTML`. → [SENT-INJ-02](../vulnerability-catalog.md#sent-inj-02--cross-site-scripting-xss)
5. **`APP_DEBUG=true` in production.** Laravel's error page (Ignition/Whoops) dumps environment,
   config, and stack traces — and has itself had RCE CVEs. →
   [SENT-SECRET-02](../vulnerability-catalog.md#sent-secret-02--permissive-cors-missing-headers-debug-mode)
6. **Outdated / abandoned WordPress plugins and themes.** The dominant WordPress breach vector: a
   plugin with a known CVE, or one no longer maintained. Nulled (pirated) plugins ship backdoors. →
   [SENT-SUPPLY-01](../vulnerability-catalog.md#sent-supply-01--unpinned-or-unmaintained-dependencies)
7. **File inclusion from a user-controlled path.** `include $_GET['page'] . '.php'` or
   `require __DIR__ . "/tpl/" . $_GET['t']` — traversal or a wrapper (`php://`, `data://`) turns it into
   code execution (LFI/RFI). → [SENT-INJ-10](../vulnerability-catalog.md#sent-inj-10--path-traversal-and-unsafe-file-path-handling)
8. **`unserialize()` on request/cookie data.** PHP object-injection via POP chains. →
   [SENT-INJ-09](../vulnerability-catalog.md#sent-inj-09--unsafe-deserialization-of-untrusted-data)

## How to test
- Request `/.env`, `/.git/config`, `/storage/logs/laravel.log` against the deployed host; every one
  must 404 or 403. Confirm the web root is the `public/` dir, not the project root.
- Grep for `->all()` into `create`/`update`, `DB::raw`/`whereRaw` with `$`, `{!! !!}`, `include`/
  `require` with `$_GET`/`$_POST`/`$_REQUEST`, and `unserialize(` on any superglobal.
- Confirm `APP_DEBUG=false` and `APP_ENV=production` in the deployed `.env`; trigger an error and
  confirm no stack trace.
- WordPress: enumerate plugin/theme versions (`wp plugin list`, or `/wp-content/plugins/*/readme.txt`)
  and cross-check against the WPScan vulnerability database; flag anything unmaintained or nulled.
- Submit extra fields on every create/update and confirm `$fillable` drops them; two-account IDOR probe
  on every route that loads a model by id.
