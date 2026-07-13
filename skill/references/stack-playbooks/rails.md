# Rails

Part of the [SENTINEL stack playbooks](../stack-playbooks.md).

## Key
Rails' conventions do a lot of security work by default — the failures come from the idioms that
bypass convention: unfiltered params, `html_safe`, string-interpolated `where`, and skipped CSRF
callbacks.

## Trust model
- `params` is attacker-controlled, nested and mass-assignable by design; **strong parameters**
  (`require`/`permit`) are the write allow-list, and a model touched by any controller without them is
  writable wholesale.
- Session cookies are signed/encrypted with `secret_key_base` — leaking it is session forgery.
- ERB auto-escapes; `html_safe`, `raw`, and `render inline:` are the XSS escape hatches — Rails'
  equivalents of `dangerouslySetInnerHTML`.

## Top traps
1. **Mass assignment.** `Model.new(params[:model])` / `update(params.to_unsafe_h)` or a `permit!`
   (permit-everything) — attacker sets `admin`, `role`, `user_id`. →
   [SENT-INJ-03](../vulnerability-catalog.md#sent-inj-03--mass-assignment--over-allocation)
2. **CSRF handling skipped.** `skip_before_action :verify_authenticity_token` added to silence a
   failing form or API controller that still uses cookie sessions. →
   [SENT-AUTHZ-09](../vulnerability-catalog.md#sent-authz-09--cross-site-request-forgery-csrf)
3. **`html_safe` / `raw` on user data** — the auto-escape bypass, often laundered through a helper. →
   [SENT-INJ-02](../vulnerability-catalog.md#sent-inj-02--cross-site-scripting-xss)
4. **SQL injection via interpolated scopes.** `where("name = '#{params[:q]}'")` instead of the
   placeholder form. → [SENT-INJ-01](../vulnerability-catalog.md#sent-inj-01--injection-sql--command--code--template)
5. **IDOR via `find`.** `Invoice.find(params[:id])` instead of `current_user.invoices.find(...)` —
   scope every lookup through the owner association. →
   [SENT-AUTHZ-01](../vulnerability-catalog.md#sent-authz-01--broken-object-level-authorization--idor)
6. **Unscoped redirects** — `redirect_to params[:return_to]` (open redirect). →
   [SENT-AUTHZ-06](../vulnerability-catalog.md#sent-authz-06--auth-redirect--oauth-callback-misconfiguration)
7. **`secret_key_base` committed**, or dev consoles reachable in production — `/rails/info`,
   a mounted web console, an exposed `rails console` over a PaaS exec. →
   [SENT-SECRET-01](../vulnerability-catalog.md#sent-secret-01--hard-coded-or-client-exposed-secrets),
   [SENT-SECRET-02](../vulnerability-catalog.md#sent-secret-02--permissive-cors-missing-headers-debug-mode)
8. **`Marshal.load` / `YAML.unsafe_load` on params or cookies.** →
   [SENT-INJ-09](../vulnerability-catalog.md#sent-inj-09--unsafe-deserialization-of-untrusted-data)

## How to test
- Run **Brakeman** — the Rails-native static scanner catches most of the above mechanically; treat its
  output as leads to verify, not a report to paste.
- Grep for `permit!`, `to_unsafe_h`, `html_safe`, `raw(`, `skip_before_action :verify_authenticity_token`,
  and `where(` / `order(` with `#{`.
- POST to a form endpoint without the CSRF token and confirm rejection; submit extra fields
  (`admin=true`) on every create/update and confirm they're dropped.
- Request `/rails/info` in the deployed configuration and confirm a 404.
- Two-account probe on every `find(params[:id])` path.
