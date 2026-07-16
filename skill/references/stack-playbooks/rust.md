# Rust (Actix-web / Axum / Rocket + SQLx / Diesel)

Part of the [SENTINEL stack playbooks](../stack-playbooks.md).

## Key
Rust's ownership model deletes the memory-corruption bug class, so be honest about where these apps
actually break: not use-after-free but *logic and config* — auth extractors forgotten on new routes,
ownership never checked in the handler, `.unwrap()` panicking the request, and the `format!` that
smuggles SQL past SQLx's compile-time checking.

## Trust model
- There is no framework auth layer. Auth is a hand-rolled extractor or middleware (an Axum extractor /
  `FromRequest` impl, `middleware::from_fn`, an Actix `.wrap(...)`), opted into per route — a route added
  later that forgets it is public.
- Ownership and tenancy are pure handler logic; the query layer enforces nothing.
- SQLx's `query!`/`query_as!` macros are checked against the live schema at compile time and
  parameterize their binds — that safety evaporates the moment a query is built with `format!`.
- A panic (`unwrap`/`expect`/slice indexing/`unreachable!`) on the request path aborts that request and,
  depending on runtime config, can take the worker task with it — a fallible op reachable from a request
  is a DoS lever, not a crash a happy-path test will surface.
- Secrets come from `Config`/env (`std::env::var`, `dotenvy`, the `config` crate); whatever is compiled
  in or committed in `.env` ships.

## Top traps
1. **Auth extractor forgotten on a new route.** Auth lives in a custom extractor / `from_fn` /
   `.wrap(Auth)` applied route-by-route; the route added later doesn't get it — the pattern-drift
   signature. →
   [SENT-ARCH-04](../vulnerability-catalog.md#sent-arch-04--context-window-pattern-abandonment),
   [SENT-AUTHZ-03](../vulnerability-catalog.md#sent-authz-03--authorization-enforced-only-in-middleware-or-network)
2. **IDOR — ownership not checked in the handler.** `query_as!(Order, "SELECT ... WHERE id = $1", id)`
   returned without `AND user_id = $2`; the macro's compile-time safety says nothing about
   authorization. →
   [SENT-AUTHZ-01](../vulnerability-catalog.md#sent-authz-01--broken-object-level-authorization--idor)
3. **`format!` into a query defeats SQLx checking.** `sqlx::query(&format!("... WHERE name = '{}'", name))`
   or Diesel `sql_query(format!(...))` — the raw-string path is neither parameterized nor
   schema-checked; use `query!`/`query_as!` with `$1` binds or Diesel's typed DSL. →
   [SENT-INJ-01](../vulnerability-catalog.md#sent-inj-01--injection-sql--command--code--template)
4. **`.unwrap()` / `.expect()` on request-path fallible ops.** Parsing a header, a DB call, slice
   indexing on user input, `serde_json::from_slice(...).unwrap()` — each is an attacker-triggered panic,
   i.e. DoS. Return `Result` and map to a status. →
   [SENT-ASYNC-01](../vulnerability-catalog.md#sent-async-01--swallowed-async-errors-and-silent-fallback-returns)
5. **Missing timeouts / cancellation on outbound work.** `reqwest` and DB calls with no
   `tokio::time::timeout` and no client-level timeout outlive the request and pile up under load, turning
   one slow dependency into resource exhaustion. →
   [SENT-INJ-05](../vulnerability-catalog.md#sent-inj-05--missing-rate-limits-on-heavy-or-metered-operations)
6. **Permissive CORS.** `tower_http::cors::CorsLayer::permissive()` / `.allow_origin(Any)`, or
   `actix_cors::Cors::permissive()` / `.allow_any_origin()` — with credentials, cross-origin
   authenticated read. →
   [SENT-SECRET-02](../vulnerability-catalog.md#sent-secret-02--permissive-cors-missing-headers-debug-mode)
7. **Untrusted input across an unbounded or `unsafe` boundary.** `serde` deserializing into types with
   `Vec`/`String`/`HashMap` fields and no size cap (memory-amplification DoS), or any `unsafe` block
   reachable from request data — raw-pointer deref, `transmute`, FFI, `get_unchecked` — which
   reintroduces the exact memory-safety class Rust otherwise removes. Cap sizes; audit every `unsafe`. →
   [SENT-INJ-09](../vulnerability-catalog.md#sent-inj-09--unsafe-deserialization-of-untrusted-data)
8. **SSRF via `reqwest`.** `reqwest::get(user_url)` reaching cloud metadata or internal services. →
   [SENT-INJ-07](../vulnerability-catalog.md#sent-inj-07--server-side-request-forgery-ssrf)
9. **Secrets in `Config`/env or a committed `.env`.** Signing keys and connection strings compiled in
   via `env!` or checked in with `.env`. →
   [SENT-SECRET-01](../vulnerability-catalog.md#sent-secret-01--hard-coded-or-client-exposed-secrets)

## How to test
- `cargo audit` — checks `Cargo.lock` against the RustSec advisory DB (the dependency-vuln gate);
  `cargo deny check` adds advisory/license/ban policy.
- `cargo clippy --all-targets -- -W clippy::unwrap_used -W clippy::expect_used -W clippy::indexing_slicing`
  flags the panic-on-request-path traps mechanically.
- Grep the escape hatches: `unsafe`, `format!(` near `query`/`sql_query`, `.unwrap()`/`.expect(` on
  request-path code, `CorsLayer::permissive`/`allow_origin(Any)`/`allow_any_origin`, `reqwest::get`,
  `std::env::var`, and a committed `.env`.
- Diff the route table against the auth extractor: list every `.route(...)`/`.service(...)`/`#[get]`/
  `#[post]` and confirm each carries the auth extractor or middleware — the one that doesn't is the bug.
- Confirm SQLx is in checked mode: queries should use `query!`/`query_as!` with `$1` binds
  (compile-time-checked against `DATABASE_URL`), not `query(&format!(...))`; run `cargo sqlx prepare --check`
  in CI to keep it honest.
- Two-account IDOR probe on every id-addressed handler; load-test the outbound-call handlers to confirm
  timeouts actually bound them.
