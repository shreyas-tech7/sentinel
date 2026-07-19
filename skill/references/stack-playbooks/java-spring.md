# Java / Spring (Servlets, Spring MVC, Spring Boot)

Part of the [SENTINEL stack playbooks](../stack-playbooks.md).

## Key
Java's type system and mature frameworks give a strong safety net — but the net only holds where the
framework's secure API was actually used. Vibe-coded Java fails at the seams: a `PreparedStatement`
used correctly on one endpoint and a `Statement` with `"... WHERE id='" + p + "'"` on the next; a
Spring Security config that secures `/admin/**` by URL pattern while a controller method it doesn't
match stays wide open. The framework makes the *secure* path verbose, so generated code often reaches
for the terse insecure one.

## Trust model
- **Servlet containers expose every `@WebServlet` / `@RequestMapping` method as a public entry point**
  unless a filter, `SecurityFilterChain`, or method-level `@PreAuthorize` gates it. URL-pattern
  security (`http.authorizeHttpRequests().requestMatchers("/admin/**")`) protects paths, not methods:
  a controller reachable by a path the matcher doesn't cover is unguarded.
- `HttpServletRequest.getParameter/getHeader/getCookies/getInputStream/getQueryString` are all
  attacker-controlled. `request.getHeader("Host")` / `X-Forwarded-*` are attacker-controlled too —
  never build reset/callback URLs from them.
- JPA/Hibernate parameterizes *bound* queries only; string-built JPQL/HQL and native queries are as
  injectable as raw JDBC.
- `@Value`-injected config and `application.properties` can carry secrets; anything logged or returned
  from an `@RestController` leaves the trust boundary.

## Top traps
1. **SQL/JPQL built by concatenation.** `Statement.executeQuery("... '" + p + "'")`,
   `connection.prepareCall("{call " + p + "}")` (a `CallableStatement` whose *statement text* is
   concatenated is still injectable), `em.createQuery("FROM User WHERE name='" + p + "'")`, or
   `createNativeQuery` with string-built SQL. The fix is bound parameters (`?`/`:name`,
   `setParameter`), not escaping. → [SENT-INJ-01](../vulnerability-catalog.md#sent-inj-01--injection-sql--command--code--template)
2. **Command injection via `Runtime.exec` / `ProcessBuilder`.** Request data concatenated into a shell
   string — `Runtime.getRuntime().exec(cmd + bar)` — or added as an argument that reaches `sh -c`.
   Prefer an argument array with a fixed executable and no shell. →
   [SENT-INJ-01](../vulnerability-catalog.md#sent-inj-01--injection-sql--command--code--template)
3. **Reflected/stored XSS from servlet output.** `response.getWriter().println(bar)`,
   `.print(bar)`, `.write(bar)`, `.format(bar, ...)` (a user-controlled *format string* is XSS **and**
   a format-string defect), or JSP `${param.x}` outside a tag that escapes. Encode at the sink
   (`encodeForHTML`, `<c:out>`, Thymeleaf `th:text`), context-appropriately. →
   [SENT-INJ-02](../vulnerability-catalog.md#sent-inj-02--cross-site-scripting-xss)
4. **Method-level authorization gaps.** URL-pattern security in `SecurityFilterChain` leaves service
   and controller methods unguarded when the pattern doesn't match, or when a new controller is added
   under a path the config never enumerated. Prefer `@PreAuthorize`/`@PostAuthorize` at the method,
   and verify object ownership — not just authentication — for every `findById(id)` reached by request
   input. → [SENT-AUTHZ-01](../vulnerability-catalog.md#sent-authz-01--broken-object-level-authorization--idor),
   [SENT-AUTHZ-03](../vulnerability-catalog.md#sent-authz-03--authorization-enforced-only-in-middleware-or-network)
5. **Mass assignment via `@ModelAttribute` / direct entity binding.** Binding a request body straight
   onto a JPA entity (`@ModelAttribute User`, or Jackson deserializing into the entity) lets an
   attacker set `role`, `enabled`, `price`. Bind to a DTO with only the writable fields, or use
   `@InitBinder` allow-lists. → [SENT-INJ-03](../vulnerability-catalog.md#sent-inj-03--mass-assignment--over-allocation)
6. **Weak crypto and hashing primitives.** `Cipher.getInstance("DES/...")` or `"AES/ECB/..."`,
   `MessageDigest.getInstance("MD5"|"SHA-1")` for anything security-relevant, `new Random()` /
   `Math.random()` minting tokens/session ids/`rememberMe` values. Note the algorithm may be read from
   a properties file — **resolve the configured value** before deciding (a `getProperty("alg","AES")`
   default is not the running value if the file overrides it). Use `SecureRandom`, AES-GCM, and
   Argon2id/bcrypt/PBKDF2 for passwords. → [SENT-CRYPTO-01](../vulnerability-catalog.md#sent-crypto-01--weak-or-absent-credential-hashing),
   [SENT-CRYPTO-02](../vulnerability-catalog.md#sent-crypto-02--predictable-randomness-in-security-sensitive-values)
7. **Insecure cookies.** `new Cookie(...)` added without `setSecure(true)` / `setHttpOnly(true)`, or
   `server.servlet.session.cookie.secure=false`. → [SENT-SECRET-03](../vulnerability-catalog.md#sent-secret-03--public-storage-buckets--default-open-configuration)
8. **Trust-boundary violations into the session.** `request.getSession().setAttribute(key, userValue)`
   or `putValue` with attacker-controlled key or value stores untrusted data in the trusted session
   zone (CWE-501); HTML-escaping does not sanitize this — the value is still user-derived. →
   [SENT-INJ-08](../vulnerability-catalog.md#sent-inj-08--excessive-data-exposure-in-responses)
9. **XXE, path traversal, SSRF, unsafe deserialization** — `DocumentBuilderFactory` /
   `XMLInputFactory` without `disallow-doctype-decl`; `new File(dir + userPath)` /
   `Paths.get(userPath)` with no containment check; `new URL(userInput).openStream()`; and
   `ObjectInputStream.readObject()` on untrusted bytes are the classic Java sinks. →
   [SENT-INJ-10](../vulnerability-catalog.md#sent-inj-10--path-traversal-and-unsafe-file-path-handling),
   [SENT-INJ-07](../vulnerability-catalog.md#sent-inj-07--server-side-request-forgery-ssrf),
   [SENT-INJ-09](../vulnerability-catalog.md#sent-inj-09--unsafe-deserialization-of-untrusted-data)
10. **Swallowed exceptions.** `catch (Exception e) {}` or a catch that only logs and returns
    `null`/`""` on an auth, validation, or crypto path fails open. →
    [SENT-ASYNC-01](../vulnerability-catalog.md#sent-async-01--swallowed-async-errors-and-silent-fallback-returns)

## How to test
- Grep for the raw sinks: `Statement`/`createStatement`/`prepareCall(` with `+`, `createQuery(`/
  `createNativeQuery(` with `+`, `Runtime.getRuntime().exec`, `ProcessBuilder`, `getWriter().print`,
  `MessageDigest.getInstance`, `Cipher.getInstance`, `new Random(`, `new Cookie(`, `readObject(`,
  `setAttribute(`. Each hit is a *lead* — trace whether request data reaches it and whether a bound
  parameter / encoder / containment check sits in between.
- **Resolve indirection before judging.** Benchmark-style code (and real code) routes taint through
  inner classes, collections, `switch`/ternary guards, and Base64 round-trips that preserve the value,
  and reads algorithms from `*.properties`. Follow the value to the sink and open the config file;
  a constant-reassignment or a safe map key kills the flow, a passthrough or `getProperty` override
  does not.
- Map the `SecurityFilterChain` / `@EnableWebSecurity` config against the actual controller inventory:
  list every `@RequestMapping`/`@GetMapping`/servlet and confirm each is covered by a matcher *and*
  by an object-level ownership check where it loads by id.
- Run SpotBugs + **Find Security Bugs**, and `mvn dependency-check:check` (OWASP Dependency-Check) for
  vulnerable libraries. Treat their output as Phase 3 leads, never as findings. →
  [SENT-SUPPLY-01](../vulnerability-catalog.md#sent-supply-01--unpinned-or-unmaintained-dependencies)
