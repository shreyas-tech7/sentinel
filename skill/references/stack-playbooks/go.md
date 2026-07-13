# Go (net/http and common frameworks)

Part of the [SENTINEL stack playbooks](../stack-playbooks.md).

## Key
Go gives you almost no framework safety net — no default middleware, no ORM, no exceptions. The
vibe-coding failures are therefore *omissions the compiler tolerates*: ignored error returns, shared
state without a mutex, and requests without contexts.

## Trust model
- Every handler registered on a mux is public unless its own code checks auth — there is no
  framework-level session layer unless one was explicitly added.
- Goroutines are cheap and generated code spawns them freely; any variable reachable from two
  goroutines is shared state, and the memory model makes unsynchronized access undefined, not just racy.
- Errors are values: an ignored return *is* a swallowed error, silently.

## Top traps
1. **Goroutine races on shared state.** Handler closures writing package-level maps/slices/counters
   with no `sync.Mutex`; caches and "simple" in-memory sessions are the classic sites. →
   [SENT-ASYNC-02](../vulnerability-catalog.md#sent-async-02--non-atomic-writes-to-shared-state)
2. **Error-swallowing via ignored returns.** `result, _ := doAuth(...)`, `val, _ := strconv.Atoi(...)`,
   or an `if err != nil` that logs and falls through to the success path — fail-open in the language's
   most idiomatic clothing. → [SENT-ASYNC-01](../vulnerability-catalog.md#sent-async-01--swallowed-async-errors-and-silent-fallback-returns)
3. **Missing context cancellation.** Handlers ignoring `r.Context()`: DB queries and outbound calls
   with no deadline outlive the request, pile up under load, and turn a slow dependency into
   resource exhaustion. → [SENT-INJ-05](../vulnerability-catalog.md#sent-inj-05--missing-rate-limits-on-heavy-or-metered-operations)
4. **SQL built with `fmt.Sprintf`.** `db.Query(fmt.Sprintf("... WHERE id = %s", id))` instead of
   placeholder args. → [SENT-INJ-01](../vulnerability-catalog.md#sent-inj-01--injection-sql--command--code--template)
5. **Auth middleware wrapped per-route by hand** — and forgotten on the routes added later (the
   pattern-abandonment signature). → [SENT-ARCH-04](../vulnerability-catalog.md#sent-arch-04--context-window-pattern-abandonment),
   [SENT-AUTHZ-03](../vulnerability-catalog.md#sent-authz-03--authorization-enforced-only-in-middleware-or-network)
6. **`filepath.Join` with request input and no containment check.** →
   [SENT-INJ-10](../vulnerability-catalog.md#sent-inj-10--path-traversal-and-unsafe-file-path-handling)

## How to test
- `go test -race ./...` and `go vet ./...` — the race detector is the definitive test for trap 1; run
  it with real concurrent load if tests don't exercise handlers.
- `errcheck ./...` (or `golangci-lint` with errcheck enabled) mechanically finds ignored error returns;
  review each hit on an auth/validation path as a potential fail-open.
- Grep for `fmt.Sprintf` feeding `Query`/`Exec`, for `go func` touching package-level vars, and for
  handlers that never read `r.Context()`.
- Diff the route table against the middleware wrapping: list every registered route and confirm each
  one passes through the auth chain.
