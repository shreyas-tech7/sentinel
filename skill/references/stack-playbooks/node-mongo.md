# Node + MongoDB (Express / Mongoose)

Part of the [SENTINEL stack playbooks](../stack-playbooks.md).

## Key
Mongo doesn't have SQL's string-concatenation injection — it has something subtler. Queries are
objects, and the danger is letting the *client control the object's shape*: a JSON body that smuggles
in a query operator (`$ne`, `$gt`, `$where`) turns a lookup into a bypass. Express, like Go, ships no
default auth, so every route is public until its own code checks.

## Trust model
- A request body parsed as JSON becomes a JavaScript object, and Mongo query methods take objects. If
  that object flows into a query unvalidated, the client chose the *operators*, not just the values.
- Express middleware is the only auth layer that exists; a route without it is open, however internal.
- Mongoose schemas are the write allow-list — but only if `strict` mode is on and the route doesn't
  spread `req.body` into the write.

## Top traps
1. **NoSQL operator injection.** `User.findOne({ username, password })` where `password` is
   `req.body.password` and the client sends `{"password": {"$ne": null}}` — the query matches any
   record and logs the attacker in. Same class via `$gt`, `$regex`, and `$where` (which runs
   server-side JS). → [SENT-INJ-01](../vulnerability-catalog.md#sent-inj-01--injection-sql--command--code--template)
2. **Missing schema validation before writes.** `new Model(req.body).save()` or
   `Model.updateOne(filter, req.body)` with a permissive schema — mass assignment of `role`, `isAdmin`,
   `balance`. Set `{ strict: true }` and allow-list the fields. →
   [SENT-INJ-03](../vulnerability-catalog.md#sent-inj-03--mass-assignment--over-allocation)
3. **`$where` / `mapReduce` with any user input** — server-side JavaScript execution inside the
   database. There is no safe way to interpolate user data here; forbid it. →
   [SENT-INJ-01](../vulnerability-catalog.md#sent-inj-01--injection-sql--command--code--template)
4. **IDOR via `findById`.** `Order.findById(req.params.id)` with no owner scope — add
   `{ _id: id, userId: req.user.id }`. → [SENT-AUTHZ-01](../vulnerability-catalog.md#sent-authz-01--broken-object-level-authorization--idor)
5. **Route with no auth middleware.** A handler added after the `app.use(requireAuth)` block, or
   mounted on a router that never got it. → [SENT-AUTHZ-04](../vulnerability-catalog.md#sent-authz-04--missing-auth-on-server-actions--route-handlers),
   [SENT-ARCH-04](../vulnerability-catalog.md#sent-arch-04--context-window-pattern-abandonment)
6. **Excessive data exposure.** `res.json(user)` returning the full Mongoose document including
   `passwordHash` and internal fields — set `select: false` on sensitive paths or project explicitly. →
   [SENT-INJ-08](../vulnerability-catalog.md#sent-inj-08--excessive-data-exposure-in-responses)

## How to test
- For every query that takes a value from `req.body`/`req.query`/`req.params`, confirm the value is
  coerced to its expected primitive type (a string stays a string) *before* it reaches the query —
  send `{"field": {"$ne": null}}` to each and confirm rejection. `express-mongo-sanitize` or a schema
  validator (Zod, Joi) at the boundary is the control.
- POST extra fields (`isAdmin: true`) on every create/update and confirm the schema drops them.
- Grep for `$where`, `mapReduce`, `req.body` spread into `save`/`update`/`create`, and `findById(`
  without an owner filter nearby.
- Two-account IDOR probe on every `findById`/`findOne` addressed by a client-supplied id.
