# .NET (ASP.NET Core MVC / Web API / Minimal APIs + EF Core)

Part of the [SENTINEL stack playbooks](../stack-playbooks.md).

## Key
ASP.NET Core is secure-by-configuration — `[Authorize]`, antiforgery, and the model binder all exist
but are opt-in per endpoint — so vibe-coded apps get breached by the endpoint that never got
`[Authorize]`, the entity bound straight from the request body, and the `FromSqlRaw` assembled with
string interpolation.

## Trust model
- `[Authorize]` is opt-in and per-endpoint (or per-controller); an action or Minimal-API route with no
  `[Authorize]` — or one still carrying `[AllowAnonymous]` from local testing — is public. A fallback
  authorization policy (`FallbackPolicy = ...RequireAuthenticatedUser()`) is the only thing that flips
  the default to deny.
- The model binder populates every public settable property of the bound type from the request;
  binding a request onto an EF Core entity is a write allow-list of "everything".
- EF Core `FindAsync`/`Find`/`Single`/`FirstOrDefault` fetch by key with no tenant scoping — ownership
  filtering is the handler's job, or a global query filter (`HasQueryFilter`).
- `appsettings.json` plus environment overrides and user-secrets are the config surface; connection
  strings and signing keys committed there ship. Data Protection keys persisted to an unprotected store
  are cookie/token forgery.
- Antiforgery is automatic for MVC form tag helpers but must be explicitly validated on API/AJAX POSTs;
  the developer exception page and detailed errors are gated on `ASPNETCORE_ENVIRONMENT`.

## Top traps
1. **`[Authorize]` missing / `[AllowAnonymous]` drift.** A new controller or Minimal API `MapPost`
   shipped without `[Authorize]`, or `[AllowAnonymous]` left on — with no fallback policy the default is
   allow. →
   [SENT-AUTHZ-04](../vulnerability-catalog.md#sent-authz-04--missing-auth-on-server-actions--route-handlers)
2. **IDOR on `FindAsync`/`Find(id)`.** `_db.Orders.FindAsync(id)` or
   `.FirstOrDefaultAsync(o => o.Id == id)` with no `&& o.TenantId == currentTenant`. →
   [SENT-AUTHZ-01](../vulnerability-catalog.md#sent-authz-01--broken-object-level-authorization--idor)
3. **Over-posting / mass assignment.** Binding the request directly to an EF entity
   (`public IActionResult Update(User user)`) instead of a DTO — attacker sets `IsAdmin`, `Role`, `Id`.
   `[Bind(nameof(...))]` allow-lists help but are easy to omit; a DTO is the real fix. →
   [SENT-INJ-03](../vulnerability-catalog.md#sent-inj-03--mass-assignment--over-allocation)
4. **EF raw SQL with interpolation.** `FromSqlRaw($"... WHERE name = '{q}'")` / `ExecuteSqlRaw(...)`
   built from a `$""` string trusts the string; use `FromSqlInterpolated`/`ExecuteSqlInterpolated` or
   `{0}` parameters. →
   [SENT-INJ-01](../vulnerability-catalog.md#sent-inj-01--injection-sql--command--code--template)
5. **Deserialization RCE.** `BinaryFormatter.Deserialize` (removed in modern .NET but still pasted),
   `JavaScriptSerializer` with a type resolver, or Json.NET `TypeNameHandling.All`/`.Auto` on untrusted
   input — attacker supplies `$type` and the gadget chain runs. →
   [SENT-INJ-09](../vulnerability-catalog.md#sent-inj-09--unsafe-deserialization-of-untrusted-data)
6. **CORS `AllowAnyOrigin().AllowCredentials()`.** Browsers reject that literal pair, so the workaround
   people reach for — `SetIsOriginAllowed(_ => true).AllowCredentials()` — reflects any origin with
   credentials: full authenticated cross-origin read. →
   [SENT-SECRET-02](../vulnerability-catalog.md#sent-secret-02--permissive-cors-missing-headers-debug-mode)
7. **Secrets in `appsettings.json`, dev exception page in prod.** Connection strings, JWT signing keys,
   and API keys committed to config; and `app.UseDeveloperExceptionPage()` unconditionally (or
   `ASPNETCORE_ENVIRONMENT=Development` deployed) dumps stack traces, config, and connection strings on
   any error. →
   [SENT-SECRET-01](../vulnerability-catalog.md#sent-secret-01--hard-coded-or-client-exposed-secrets),
   [SENT-SECRET-02](../vulnerability-catalog.md#sent-secret-02--permissive-cors-missing-headers-debug-mode)
8. **Antiforgery disabled or never validated.** `[IgnoreAntiforgeryToken]`, or cookie-authenticated API
   POSTs with no `[ValidateAntiForgeryToken]` and no global `[AutoValidateAntiforgeryToken]` filter. →
   [SENT-AUTHZ-09](../vulnerability-catalog.md#sent-authz-09--cross-site-request-forgery-csrf)
9. **SSRF via `HttpClient`.** `httpClient.GetAsync(userUrl)` reaching cloud metadata or internal
   services. →
   [SENT-INJ-07](../vulnerability-catalog.md#sent-inj-07--server-side-request-forgery-ssrf)
10. **Path traversal via `Path.Combine`.** `Path.Combine(root, userInput)` — `Path.Combine` returns the
    second arg verbatim if it's rooted, and follows `..`; canonicalize with `Path.GetFullPath` and
    verify the result stays under `root`. →
    [SENT-INJ-10](../vulnerability-catalog.md#sent-inj-10--path-traversal-and-unsafe-file-path-handling)

## How to test
- Enumerate endpoints and their auth: run the app and open Swagger (`/swagger`) if present — it lists
  every route; otherwise reflect over `[Authorize]`/`[AllowAnonymous]` attributes and Minimal-API
  `RequireAuthorization()` calls. Confirm a fallback policy exists, or that every route is individually
  protected.
- Grep the escape hatches: `AllowAnonymous`, `FromSqlRaw`, `ExecuteSqlRaw`, `TypeNameHandling`,
  `BinaryFormatter`, `JavaScriptSerializer`, `AllowAnyOrigin`, `SetIsOriginAllowed`,
  `IgnoreAntiforgeryToken`, `UseDeveloperExceptionPage`, `Path.Combine`, `new HttpClient`.
- Check binding targets: find controller actions / Minimal API handlers whose parameter type is an EF
  entity (a `DbSet<T>` element type) rather than a request DTO.
- Confirm `ASPNETCORE_ENVIRONMENT=Production` in the deployed config; trigger an error and confirm a
  generic page, not the developer exception page.
- Probe CORS: send `Origin: https://evil.example` and confirm `Access-Control-Allow-Origin` doesn't
  reflect it alongside `Access-Control-Allow-Credentials: true`.
- Two-account IDOR probe on every `Find`/`FindAsync`/`FirstOrDefault(x => x.Id == id)` endpoint, as in
  the [generic playbook](generic.md).
- Dependency and analyzer scan: `dotnet list package --vulnerable --include-transitive`; enable the
  built-in security analyzers (CA3xxx/CA5xxx) with `<AnalysisMode>All</AnalysisMode>`.
