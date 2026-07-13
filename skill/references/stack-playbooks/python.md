# Python (Django / Flask / FastAPI)

Part of the [SENTINEL stack playbooks](../stack-playbooks.md).

## Key
The frameworks ship with strong defaults (ORM parameterization, CSRF middleware, auto-escaping
templates) — vibe-coded Python apps get breached through the *escape hatches* and the settings that
were never flipped for production.

## Trust model
- Django's middleware stack, Flask's decorators, and FastAPI's dependencies are the enforcement
  points; a view/route without the right decorator or dependency (`login_required`,
  `permission_required`, `Depends(get_current_user)`) is public, however "internal" it looks.
- `settings.py` / app config is the security posture in one file: `DEBUG`, `ALLOWED_HOSTS`,
  `SECRET_KEY`, cookie flags. Whatever is in the deployed settings module is what production runs.
- Jinja2/Django templates auto-escape HTML — until someone marks content `safe`.
- FastAPI's OpenAPI docs (`/docs`, `/redoc`) enumerate every endpoint for anyone who can reach them —
  convenient for you and for an attacker mapping the surface.

## Top traps
1. **ORM injection despite the ORM.** `.raw()`, `.extra()`, `cursor.execute()` with an f-string or
   `%`-formatted SQL, or `text()` in SQLAlchemy with interpolated input — the ORM's safety only covers
   the queries that go through it. → [SENT-INJ-01](../vulnerability-catalog.md#sent-inj-01--injection-sql--command--code--template)
2. **`DEBUG = True` in production.** Django's debug page dumps settings, environment, and stack traces
   to any visitor on an error; Flask's interactive debugger is remote code execution by design (the
   console PIN is not a control). The single highest-leverage settings check. →
   [SENT-SECRET-02](../vulnerability-catalog.md#sent-secret-02--permissive-cors-missing-headers-debug-mode)
3. **CSRF protection disabled instead of configured.** `@csrf_exempt` sprinkled to make a failing POST
   work (or Flask apps with no CSRF extension at all on session-cookie-authenticated forms). →
   [SENT-AUTHZ-09](../vulnerability-catalog.md#sent-authz-09--cross-site-request-forgery-csrf)
4. **Admin panel exposed.** Django admin at the default `/admin/` with weak or reused superuser
   credentials, no IP restriction or SSO, and `DEBUG`-era accounts still active. →
   [SENT-AUTHZ-02](../vulnerability-catalog.md#sent-authz-02--broken-function-level-authorization)
5. **`SECRET_KEY` committed** (signs sessions — leaking it is session forgery), or loaded with an
   insecure fallback default (`os.environ.get("SECRET_KEY", "dev")` ships the fallback). Flask's
   tutorial-default `app.secret_key = 'dev'` is the same bug. →
   [SENT-SECRET-01](../vulnerability-catalog.md#sent-secret-01--hard-coded-or-client-exposed-secrets)
6. **Template escape hatches.** `|safe`, `mark_safe()`, `{% autoescape off %}`, `Markup()` on anything
   user-derived. → [SENT-INJ-02](../vulnerability-catalog.md#sent-inj-02--cross-site-scripting-xss)
7. **Object access by pk with no owner filter.** `get_object_or_404(Invoice, pk=pk)` without
   `owner=request.user`. → [SENT-AUTHZ-01](../vulnerability-catalog.md#sent-authz-01--broken-object-level-authorization--idor)
8. **FastAPI auth declared but never wired.** An `oauth2_scheme` / `get_current_user` dependency
   defined in `auth.py` — and absent from the route that matters: the endpoint signature has no
   `Depends`, or the dependency parses the token without verifying it. The auth code *exists*, which
   is exactly what makes the gap invisible to review (the half-present-control pattern,
   [SENT-ARCH-05](../vulnerability-catalog.md#sent-arch-05--security-focused-regression-trap)). →
   [SENT-AUTHZ-04](../vulnerability-catalog.md#sent-authz-04--missing-auth-on-server-actions--route-handlers)
9. **`yaml.load` / `pickle` on anything uploadable or fetched.** →
   [SENT-INJ-09](../vulnerability-catalog.md#sent-inj-09--unsafe-deserialization-of-untrusted-data)

## How to test
- `python manage.py check --deploy` — Django's own production checklist flags `DEBUG`, cookie flags,
  HSTS, and `SECRET_KEY` issues in one command.
- Grep for the escape hatches: `\.raw\(`, `\.extra\(`, `cursor.execute` with `f"`/`%`/`.format`,
  `@csrf_exempt`, `mark_safe`, `|safe`, `yaml.load(`, `pickle.load`.
- Request `/admin/` unauthenticated; trigger an error page in the deployed configuration and confirm a
  generic error, not the debug page.
- FastAPI: open `/docs`, enumerate every route it lists, and hit each one with no token and with
  another user's object id — the docs page is your entry-point inventory. Confirm the deployed config
  disables it if it shouldn't be public.
- Two-account IDOR probe on every pk/slug-addressed view, exactly as in the
  [generic playbook](generic.md).
