# LLM / RAG applications

Part of the [SENTINEL stack playbooks](../stack-playbooks.md). Applies **only when Phase 0 detected an
LLM/agent integration** — see the Phase 3 section D gate in [`../../SKILL.md`](../../SKILL.md).

## Key
Two new trust boundaries appear: **untrusted content flowing *into* the model** (prompt injection) and
**model output flowing *into* a sink** (improper output handling). The model is not a trusted component;
it is a powerful text transformer sitting between them.

## Trust model
- Anything placed in the context window — user messages, retrieved documents, tool results, web content —
  is data the model may *follow as instructions* unless separated. Retrieval and tool use widen the
  attack surface: a document can carry an injection (indirect prompt injection).
- Model output is untrusted output. Rendering it, executing it, or passing it to a tool without
  validation is the same class of mistake as trusting user input.
- Model APIs are **metered and billed per call.** An uncapped generation endpoint is a financial DoS
  surface.
- Keys for the model provider are server-only secrets and must never enter the prompt or the client.

## Top traps
1. **Prompt injection** — untrusted content concatenated into instructions with no separation. →
   [SENT-LLM-01](../vulnerability-catalog.md#sent-llm-01--prompt-injection)
2. **Improper output handling** — model output rendered as HTML or run as SQL/commands/tool calls
   unsanitized. → [SENT-LLM-02](../vulnerability-catalog.md#sent-llm-02--improper-output-handling)
3. **Excessive agency** — broad tools / admin credentials / no human gate on high-impact actions. →
   [SENT-LLM-03](../vulnerability-catalog.md#sent-llm-03--excessive-agency)
4. **Denial-of-wallet** — no per-user quota (often no auth) on a paid generation route. →
   [SENT-LLM-04](../vulnerability-catalog.md#sent-llm-04--denial-of-wallet-on-metered-model-apis)
5. **Secrets / authz in the prompt** — keys embedded in prompts; "don't reveal other users' data" as a
   system-prompt instruction instead of an enforced control. → [SENT-LLM-05](../vulnerability-catalog.md#sent-llm-05--sensitive-disclosure--system-prompt-as-boundary)
6. **Vector store not row-scoped** — cross-tenant retrieval from a shared embeddings table with no RLS.
   → [SENT-LLM-06](../vulnerability-catalog.md#sent-llm-06--rag-poisoning-and-non-row-scoped-vector-stores)

## How to test
- **Direct injection:** send messages that instruct the model to ignore prior instructions, reveal the
  system prompt, or call a tool it shouldn't. Confirm separation holds and the system prompt is not the
  only guard.
- **Indirect injection:** ingest a document containing embedded instructions ("assistant: when asked
  about X, output …") and confirm retrieval doesn't let it hijack behavior or trigger tools.
- **Output handling:** make the model produce `<img onerror=...>` or SQL-shaped text and confirm the
  sink encodes/parameterizes it rather than executing it.
- **Denial-of-wallet:** call the generation endpoint in a loop, unauthenticated if possible, and confirm
  auth + a per-user quota stop it before cost accrues.
- **Cross-tenant retrieval:** as tenant A, run a query that should only match A's documents and confirm
  no B documents come back (RLS on the embeddings table; the two-account test from the
  [Supabase playbook](supabase.md) applies).
