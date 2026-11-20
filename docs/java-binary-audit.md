# Java Binary White Box Audit

ARTEX uses the vendored JavaCodeDB project to index and decompile Java `.class`, JAR, WAR, and ZIP deployment artifacts. It reads uploaded artifacts as data and never executes their classes. Source-code audits continue to use ARTEX's source reader.

## Runtime

Release ZIP files contain `java-code-db.jar` next to the ARTEX executable, and the Go binary also carries a compressed fallback copy for upgrades from older ARTEX versions. Binary audits require Java 21 or newer on the host; the Docker image includes a Java 21 runtime. Set `ARTEX_JAVA_BIN` only when Java is not available as `java` on `PATH`. Set `ARTEX_JAVACODEDB_JAR` only to override the bundled JAR with an absolute path.

The backend reports binary audit availability in the service audit configuration. Uploading code does not start a security audit. A user must select a service and explicitly start its audit.

## Audit behavior

Each selected service gets an independent JavaCodeDB workspace under its task and immutable codebase version. ARTEX disables JavaCodeDB's shared cross-workspace decompilation cache, sets one index worker per service, and keeps the existing limit of four concurrently audited services. Completed service slots are filled from the pending queue.

The audit agent queues application classes by default, then uses JavaCodeDB search and call-graph results to read dependencies as needed. It can search symbols and method bodies, inspect detected web endpoints, query callers and callees, and read bounded CFR-decompiled class source with line numbers. JavaCodeDB index and workspace files stay scoped to that task version and are removed with the task's codebase data.

Source and binary audits use the same tiered registration rules. The worker checks candidates against code read within the current chunk; there is no independent LLM review:

- **A:** Complete static source-to-sink evidence, blocking-condition analysis, and exploitability conditions. Register a pending Finding with verification level `theoretical` and queue the report agent.
- **B:** Real, read source/sink locations and symbols, with gaps in propagation, controls, exploitability, excerpt matching, or sink API heuristics. Register a pending, `theoretical` Finding with low confidence and the platform's validation reasons. Do not automatically queue the report agent. Default priority sorting places these leads after findings with complete evidence; explicit time sorting retains chronological order.
- **C:** Unread lines, out-of-scope files, missing source/sink anchors, absent symbols, invalid required structure, or missing binary provenance. Retain the candidate as `incomplete` with reasons and do not register a Finding.

The worker feeds validation failures back to the model once within the same chunk, using the same scoped read-only tools and token controls. Candidates omitted by the repair remain available for registration or incomplete storage. Registration tier and validation reasons are platform-owned metadata in `code_audit_evidence` and the candidate JSON. Same-version B observations cannot overwrite A evidence; promotion from B to A can trigger a report. None of these tiers proves successful dynamic exploitation.

Binary provenance records the JavaCodeDB JAR SHA-256, uploaded artifact SHA-256, original class entry, package, class, and method for the source and sink. This binds the evidence to the selected immutable artifact and the JavaCodeDB build used to reconstruct it.
