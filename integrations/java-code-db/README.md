# JavaCodeDB

JavaCodeDB builds a persistent local search index from Java `.class` files, JARs, and deployment archives. It exposes the index through a CLI or an MCP stdio server. The Java implementation uses Lucene for search and CFR for bytecode decompilation; it reads deployment files as data and does not execute them.

## Build

Requires JDK 21 and Maven.

```sh
mvn package
```

The executable JAR is written to `target/java-code-db-0.1.0-SNAPSHOT.jar`. The commands below use `java -jar target/java-code-db-0.1.0-SNAPSHOT.jar` (Java 21+); ARTEX itself builds and embeds this JAR through `scripts/build-java-code-db.sh`.

## CLI

The workspace defaults to the current directory. `init` creates or updates its symbol index, then returns while a detached background task prewarms method bodies across sessions. It processes application classes first and dependencies second. Later searches use the saved index without rescanning artifacts.

Class scope is inferred from archive paths. To include internal libraries packaged under dependency paths, JavaCodeDB reads class paths under `BOOT-INF/classes` and infers each reverse-domain prefix from its first two package segments (for example, `com.simia` from `com/simia/service/OrderService.class`). Classes in `BOOT-INF/lib`, `WEB-INF/lib`, `lib`, or `libs` that share one of those package prefixes are classified as application classes and prewarmed with the application scope. Package matching respects segment boundaries, so `com.simiax` does not match `com.simia`.

```sh
java -jar target/java-code-db-0.1.0-SNAPSHOT.jar init --workspace /path/to/deployment
java -jar target/java-code-db-0.1.0-SNAPSHOT.jar status --workspace /path/to/deployment
java -jar target/java-code-db-0.1.0-SNAPSHOT.jar search-code --workspace /path/to/deployment \
  --query "OrderService" --scope all --mode text --limit 10
java -jar target/java-code-db-0.1.0-SNAPSHOT.jar search-code --workspace /path/to/deployment \
  --query "executeUpdate" --include-bodies true
java -jar target/java-code-db-0.1.0-SNAPSHOT.jar search-config --workspace /path/to/deployment --query "spring datasource"
java -jar target/java-code-db-0.1.0-SNAPSHOT.jar get-method --workspace /path/to/deployment \
  --class-name com.example.OrderService --method-name place
```

Commands include `init`, `refresh`, `status`, `search-code`, `search-config`, `get-method`, `list-web-endpoints`, `find-callers`, `find-callees`, and `prewarm` (resume staged body indexing). The MCP server also exposes `list_classes` and `get_class_source` so callers can enumerate class provenance and retrieve bounded, line-numbered CFR source ranges. Code search supports text, substring, and regex modes over symbols by default. Use `--include-bodies true` to wait for background indexing, finish any remaining work in the requested artifact scope (default `all`), and search decompiled method text. Application-scope body search can proceed as soon as the application phase is committed, while dependency prewarming continues. Search responses include `bodySearchComplete`; treat `false` as a partial body search. `status` reports `bodyPrewarmState`, phase, processed/total counts, and percentage. Writable CLI commands wait for an active prewarm to finish so they do not compete for Lucene's writer lock. `get-method` decompiles only the requested class and caches the result. Caller/callee searches lazily scan bytecode instructions across the workspace once, without decompiling source. Status reports `graphIndexState` and `bodyIndexState`. Call graph traversal defaults to depth three. Run `java -jar target/java-code-db-0.1.0-SNAPSHOT.jar --help` for options.

## Indexing Throughput

Class parsing uses a bounded worker pool. Decompilation and method extraction use that same pool for background body prewarming, `get-method`, and explicit full-body search. The default is up to four workers, limited by the available CPU count; the queue applies backpressure while scanning large archives. Set `JAVACODEDB_INDEX_WORKERS` to a value from `1` to `8` to tune indexing, for example `JAVACODEDB_INDEX_WORKERS=8 java -jar target/java-code-db-0.1.0-SNAPSHOT.jar init --workspace /path/to/deployment`. Each worker reuses its decompiler process and temporary class file.

Lucene buffers documents before writing index segments. The default RAM buffer is 16 MB. Set `JAVACODEDB_LUCENE_RAM_BUFFER_MB` (16–512) to tune it, for example `JAVACODEDB_LUCENE_RAM_BUFFER_MB=64 java -jar target/java-code-db-0.1.0-SNAPSHOT.jar init --workspace /path/to/deployment`. The active value is reported by `status` as `luceneRamBufferMb`.

Expensive call-graph and method-body analysis results are cached by SHA-256 and reused across workspaces. The shared cache defaults to `~/.javacodedb/cache`; older entries are evicted if it exceeds its 4 GB target. Override it with `JAVACODEDB_CACHE_DIR`; set `JAVACODEDB_CACHE_ENABLED=false` to disable it. Cache entries may include decompiled code, so keep the cache directory private or remove it when no longer needed.

## MCP

Run the JAR as an MCP stdio process bound to one workspace:

```sh
java -jar target/java-code-db-0.1.0-SNAPSHOT.jar --workspace /path/to/deployment
```

Configure an MCP client with the same command and arguments. The server exposes status, refresh, code/config search, method lookup, endpoint listing, and caller/callee tools. `list_classes` accepts `scope=application`, `scope=dependency`, or `scope=all`; `get_class_source` can select a class by name or by an exact artifact and archive-entry pair. On startup or refresh it builds symbols first, then prewarms method bodies in the background, application before dependencies. `get_index_status` reports progress; application-scope body searches become available before dependency prewarming finishes.

The persistent Lucene index is stored under `<workspace>/.javacodedb/lucene`. By default it contains symbols, call edges only after graph hydration, and configuration values; enabling body indexing also stores decompiled code. Restrict access to that directory.
