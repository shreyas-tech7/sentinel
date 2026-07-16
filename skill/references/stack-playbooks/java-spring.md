# Java / Spring (Spring Boot / Spring Security / Spring MVC / Spring Data JPA)

Part of the [SENTINEL stack playbooks](../stack-playbooks.md).

## Key
Spring Security gives you two enforcement layers — a URL filter chain and method security — and
vibe-coded Spring apps get breached when those layers drift apart, when `permitAll()` /
`csrf().disable()` get pasted to make a request work, and when JPA's `findById` hands back any row by
primary key with no owner check.

## Trust model
- Two layers that must agree: the `SecurityFilterChain` (`authorizeHttpRequests`, URL-pattern based)
  and method security (`@PreAuthorize`/`@PostAuthorize`). Method security only runs if
  `@EnableMethodSecurity` (Boot 3) / `@EnableGlobalMethodSecurity` (older) is present — without it
  every `@PreAuthorize` is decorative. A controller method guarded at neither layer is
  authenticated-but-unauthorized: any logged-in user reaches it.
- `permitAll()`, `csrf().disable()`, and `anyRequest().permitAll()` in the chain are the whole posture
  in a few lines; a broad `permitAll()` or a mis-ordered matcher exposes everything it covers.
- Spring Data JPA repositories (`findById`, `getReferenceById`) fetch by primary key with zero
  tenancy awareness — ownership is the handler's job, never the repository's.
- Request binding (`@ModelAttribute`, `@RequestBody` onto an `@Entity`) populates every settable field
  from the request unless a DTO or field allow-list narrows it.
- Actuator endpoints and the auto-generated error surface expose internal state; whatever
  `management.endpoints.web.exposure.include` lists is reachable, and `/actuator/heapdump` is a memory
  dump.

## Top traps
1. **`@PreAuthorize` missing, or method security never enabled.** No `@EnableMethodSecurity` means
   every `@PreAuthorize` is dead annotation; and `@PreAuthorize("hasRole('USER')")` still authorizes by
   role, not ownership — any user reaches any tenant's object. →
   [SENT-AUTHZ-02](../vulnerability-catalog.md#sent-authz-02--broken-function-level-authorization)
2. **Filter-chain gaps and `permitAll()`.** `requestMatchers("/api/**").permitAll()` pasted to silence a
   401, `anyRequest().permitAll()`, or matcher ordering that puts a broad permit ahead of the
   authenticated rule. →
   [SENT-AUTHZ-04](../vulnerability-catalog.md#sent-authz-04--missing-auth-on-server-actions--route-handlers)
3. **`csrf().disable()` on a cookie-session app.** The reflexive fix for a failing POST; if the app
   authenticates with a session cookie, CSRF protection is now off. →
   [SENT-AUTHZ-09](../vulnerability-catalog.md#sent-authz-09--cross-site-request-forgery-csrf)
4. **IDOR on `repository.findById(id)`.** `orderRepo.findById(id).orElseThrow()` returned straight to
   the caller with no `owner = currentUser` predicate. →
   [SENT-AUTHZ-01](../vulnerability-catalog.md#sent-authz-01--broken-object-level-authorization--idor)
5. **Mass assignment via direct entity binding.** A handler taking `@ModelAttribute User user` or
   `@RequestBody User user` straight onto the `@Entity` — attacker posts `role=ADMIN`, `enabled=true`,
   `id=…`. Bind a DTO or allow-list fields with `@InitBinder`/`setAllowedFields`. →
   [SENT-INJ-03](../vulnerability-catalog.md#sent-inj-03--mass-assignment--over-allocation)
6. **JPQL / native SQL string concatenation.** `@Query("... where email = '" + email + "'")`, or
   `entityManager.createQuery(...)` / `createNativeQuery(...)` built with `+` — defeats parameter
   binding; use `:named` binds. →
   [SENT-INJ-01](../vulnerability-catalog.md#sent-inj-01--injection-sql--command--code--template)
7. **SpEL injection.** User input reaching `ExpressionParser.parseExpression(...)`, or a
   `@PreAuthorize`/`@Value` expression assembled from request data — evaluates arbitrary expressions,
   i.e. RCE. →
   [SENT-INJ-01](../vulnerability-catalog.md#sent-inj-01--injection-sql--command--code--template)
8. **Insecure deserialization.** Native `ObjectInputStream.readObject()` on untrusted bytes, or Jackson
   polymorphic typing (`enableDefaultTyping()`/`activateDefaultTyping(...)`, `@JsonTypeInfo(use = Id.CLASS)`)
   on attacker JSON — gadget-chain RCE. →
   [SENT-INJ-09](../vulnerability-catalog.md#sent-inj-09--unsafe-deserialization-of-untrusted-data)
9. **SSRF via `RestTemplate` / `WebClient`.** `restTemplate.getForObject(userUrl, …)` or
   `webClient.get().uri(userUrl)` reaching cloud metadata or internal services. →
   [SENT-INJ-07](../vulnerability-catalog.md#sent-inj-07--server-side-request-forgery-ssrf)
10. **Actuator exposed and secrets in config.** `management.endpoints.web.exposure.include=*` opens
    `/actuator/env`, `/actuator/heapdump`, `/actuator/mappings` (heapdump leaks in-memory secrets, env
    leaks config); plus credentials hard-coded in `application.properties`/`application.yml`. →
    [SENT-SECRET-02](../vulnerability-catalog.md#sent-secret-02--permissive-cors-missing-headers-debug-mode),
    [SENT-SECRET-01](../vulnerability-catalog.md#sent-secret-01--hard-coded-or-client-exposed-secrets)

## How to test
- Enumerate the surface: with Actuator on, `/actuator/mappings` lists every route and its handler;
  otherwise run with `logging.level.org.springframework.security=DEBUG` to log the filter chain and the
  matched rule per request. Confirm every data/state-changing route requires auth.
- Confirm method security is actually on: grep for `@EnableMethodSecurity` /
  `@EnableGlobalMethodSecurity` — if absent, every `@PreAuthorize` is inert. Then list every
  `@PreAuthorize`/`@PostAuthorize` and check each guards ownership, not just a role.
- Grep the escape hatches: `csrf().disable`, `permitAll(`, `anyRequest().permitAll`,
  `createNativeQuery`, `createQuery(` and `@Query(` with `+`, `enableDefaultTyping`,
  `activateDefaultTyping`, `@JsonTypeInfo`, `readObject(`, `parseExpression(`, `new RestTemplate`,
  `WebClient`.
- Probe Actuator unauthenticated: request `/actuator`, `/actuator/env`, `/actuator/heapdump`,
  `/actuator/beans`; a downloadable heapdump is in-memory secrets. Confirm `exposure.include` isn't `*`
  in the deployed profile.
- Two-account IDOR probe on every `findById`/`getReferenceById`-addressed endpoint, as in the
  [generic playbook](generic.md).
- Dependency scan: `mvn org.owasp:dependency-check-maven:check` or `gradle dependencyCheckAnalyze`
  (catches Log4Shell-era `log4j-core`, vulnerable Jackson/SnakeYAML); `mvn versions:display-dependency-updates`
  for staleness.
