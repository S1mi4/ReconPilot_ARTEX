package io.javacodedb;

import org.apache.lucene.analysis.Analyzer;
import org.apache.lucene.analysis.Tokenizer;
import org.apache.lucene.analysis.ngram.NGramTokenizer;
import org.apache.lucene.analysis.miscellaneous.PerFieldAnalyzerWrapper;
import org.apache.lucene.analysis.standard.StandardAnalyzer;
import org.apache.lucene.document.Document;
import org.apache.lucene.index.DirectoryReader;
import org.apache.lucene.index.IndexWriter;
import org.apache.lucene.index.IndexWriterConfig;
import org.apache.lucene.index.Term;
import org.apache.lucene.queryparser.classic.MultiFieldQueryParser;
import org.apache.lucene.search.BooleanClause;
import org.apache.lucene.search.BooleanQuery;
import org.apache.lucene.search.BoostQuery;
import org.apache.lucene.search.FieldExistsQuery;
import org.apache.lucene.search.IndexSearcher;
import org.apache.lucene.search.Query;
import org.apache.lucene.search.SearcherManager;
import org.apache.lucene.search.TermQuery;
import org.apache.lucene.search.TermInSetQuery;
import org.apache.lucene.search.TopDocs;
import org.apache.lucene.store.Directory;
import org.apache.lucene.store.FSDirectory;
import org.apache.lucene.util.BytesRef;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Consumer;

import com.google.re2j.Pattern;

final class IndexService implements AutoCloseable {
    private static final String INDEX_SCHEMA_VERSION = "6";
    private static final int MAX_PAGE_SIZE = 50;
    private static final int MAX_OFFSET = 1_000;
    private static final int MAX_SEARCH_HITS = 1_050;
    private static final int DEFAULT_INDEX_WORKERS = 4;
    private static final int MAX_INDEX_WORKERS = 8;
    private static final int MIN_LUCENE_RAM_BUFFER_MB = 16;
    private static final int MAX_LUCENE_RAM_BUFFER_MB = 512;

    private final Path workspace;
    private final Path indexHome;
    private final Path lucenePath;
    private final Path temporaryPath;
    private final Analyzer analyzer = createAnalyzer();
    private final Directory directory;
    private final IndexWriter writer;
    private final SearcherManager searchers;
    private final boolean readOnly;
    private final int indexWorkerCount;
    private final int luceneRamBufferMb;
    private final BytecodeIndexer bytecodeIndexer = new BytecodeIndexer();
    private final DecompileWorkerPool decompileWorkers;
    private final ClassIndexCache classIndexCache;
    private final ExecutorService refreshExecutor = Executors.newSingleThreadExecutor(task -> {
        Thread thread = new Thread(task, "javacodedb-indexer");
        thread.setDaemon(true);
        return thread;
    });
    private final AtomicBoolean refreshRunning = new AtomicBoolean();
    private final AtomicBoolean refreshAfterBodyPrewarm = new AtomicBoolean();
    private final Object refreshMonitor = new Object();
    private final AtomicBoolean bodyPrewarmRunning = new AtomicBoolean();
    private final AtomicLong lastBodyPrewarmPersistNanos = new AtomicLong();
    private final ReentrantLock bodyHydrationLock = new ReentrantLock(true);
    private volatile boolean stagedBodyPrewarm;
    private volatile boolean autoPrewarmAfterRefresh;

    private volatile String state = "starting";
    private volatile String lastStartedAt = "";
    private volatile String lastCompletedAt = "";
    private volatile long classesFound;
    private volatile long classesIndexed;
    private volatile long methodsIndexed;
    private volatile long classesWithGraphIndexed;
    private volatile String graphIndexState = "unknown";
    private volatile long classesWithBodiesIndexed;
    private volatile String bodyIndexState = "unknown";
    private volatile String bodyPrewarmState = "not_started";
    private volatile String bodyPrewarmPhase = "idle";
    private volatile String bodyPrewarmTargetScope = "all";
    private volatile long bodyPrewarmProcessed;
    private volatile long bodyPrewarmTotal;
    private volatile String bodyPrewarmStartedAt = "";
    private volatile String bodyPrewarmCompletedAt = "";
    private volatile String bodyPrewarmIssue = "";
    private volatile long resourcesIndexed;
    private volatile long classesSkipped;
    private volatile long resourcesSkipped;
    private volatile long missingDependencyTypes;
    private volatile long unsupportedClassFiles;
    private volatile long classParseErrors;
    private volatile long decompilerFailures;
    private volatile List<String> missingDependencyExamples = List.of();
    private volatile long errors;
    private final AtomicLong processed = new AtomicLong();
    private volatile long classCacheHits;
    private volatile long classCacheMisses;
    private volatile boolean classCacheEnabled;
    private volatile String classCacheDirectory = "";
    private volatile long refreshDurationMs;
    private volatile List<String> recentIssues = List.of();

    IndexService(Path workspace) throws IOException {
        this(workspace, false);
    }

    IndexService(Path workspace, boolean readOnly) throws IOException {
        this.workspace = workspace;
        this.indexHome = workspace.resolve(".javacodedb");
        this.lucenePath = indexHome.resolve("lucene");
        this.temporaryPath = indexHome.resolve("tmp");
        this.readOnly = readOnly;
        this.indexWorkerCount = configuredIndexWorkerCount();
        this.luceneRamBufferMb = configuredLuceneRamBufferMb();
        if (!readOnly) {
            Files.createDirectories(lucenePath);
            Files.createDirectories(temporaryPath);
        } else if (!Files.isDirectory(lucenePath)) {
            throw new IllegalStateException("Index is not initialized: " + indexHome);
        }
        this.decompileWorkers = new DecompileWorkerPool(indexWorkerCount, temporaryPath);
        this.classIndexCache = ClassIndexCache.configured();
        this.classCacheEnabled = classIndexCache.enabled();
        this.classCacheDirectory = classIndexCache.directory().toString();
        this.directory = FSDirectory.open(lucenePath);
        IndexWriter openedWriter = null;
        SearcherManager openedSearchers = null;
        try {
            if (readOnly) {
                if (!DirectoryReader.indexExists(directory)) {
                    throw new IllegalStateException("Index is not initialized: " + indexHome);
                }
                try (DirectoryReader reader = DirectoryReader.open(directory)) {
                    String schemaVersion = reader.getIndexCommit().getUserData().get("schemaVersion");
                    if (!INDEX_SCHEMA_VERSION.equals(schemaVersion)) {
                        throw new IllegalStateException("Index schema is outdated; run `init` or `refresh` to rebuild it");
                    }
                }
                openedSearchers = new SearcherManager(directory, new org.apache.lucene.search.SearcherFactory());
            } else {
                openedWriter = new IndexWriter(directory, new IndexWriterConfig(analyzer)
                        .setOpenMode(IndexWriterConfig.OpenMode.CREATE_OR_APPEND)
                        .setRAMBufferSizeMB(luceneRamBufferMb));
                Map<String, String> commitData = new HashMap<>();
                for (Map.Entry<String, String> item : openedWriter.getLiveCommitData()) {
                    commitData.put(item.getKey(), item.getValue());
                }
                if (!INDEX_SCHEMA_VERSION.equals(commitData.get("schemaVersion"))) {
                    openedWriter.deleteAll();
                }
                commitData.put("schemaVersion", INDEX_SCHEMA_VERSION);
                openedWriter.setLiveCommitData(commitData.entrySet());
                openedWriter.commit();
                openedSearchers = new SearcherManager(openedWriter, new org.apache.lucene.search.SearcherFactory());
            }
        } catch (IOException | RuntimeException e) {
            if (openedSearchers != null) {
                try { openedSearchers.close(); } catch (IOException ignored) { }
            }
            if (openedWriter != null) {
                try { openedWriter.close(); } catch (IOException ignored) { }
            }
            try { directory.close(); } catch (IOException ignored) { }
            analyzer.close();
            throw e;
        }
        this.writer = openedWriter;
        this.searchers = openedSearchers;
        loadPersistedStatus();
    }

    static boolean isCurrentSchema(Path workspace) throws IOException {
        Path lucenePath = workspace.resolve(".javacodedb").resolve("lucene");
        if (!Files.isDirectory(lucenePath)) return false;
        try (Directory directory = FSDirectory.open(lucenePath)) {
            if (!DirectoryReader.indexExists(directory)) return false;
            try (DirectoryReader reader = DirectoryReader.open(directory)) {
                return INDEX_SCHEMA_VERSION.equals(reader.getIndexCommit().getUserData().get("schemaVersion"));
            }
        }
    }

    static boolean isBodyScopeComplete(Path workspace, String scope) throws IOException {
        String normalizedScope = normalizeArtifactScope(scope);
        Path lucenePath = workspace.resolve(".javacodedb").resolve("lucene");
        if (!Files.isDirectory(lucenePath)) return false;
        try (Directory directory = FSDirectory.open(lucenePath)) {
            if (!DirectoryReader.indexExists(directory)) return false;
            try (DirectoryReader reader = DirectoryReader.open(directory)) {
                if (!INDEX_SCHEMA_VERSION.equals(reader.getIndexCommit().getUserData().get("schemaVersion"))) {
                    return false;
                }
                IndexSearcher searcher = new IndexSearcher(reader);
                Query scopedClasses = classQueryInScope(normalizedScope);
                Query indexedBodies = new BooleanQuery.Builder()
                        .add(scopedClasses, BooleanClause.Occur.MUST)
                        .add(new TermQuery(new Term("bodyIndexed", "true")), BooleanClause.Occur.MUST)
                        .build();
                return searcher.count(indexedBodies) >= searcher.count(scopedClasses);
            }
        }
    }

    void startBackgroundRefresh() {
        if (readOnly) {
            throw new IllegalStateException("The index is open read-only");
        }
        requestRefresh();
    }

    void startBackgroundRefresh(boolean prewarmBodiesAfterRefresh) {
        autoPrewarmAfterRefresh = prewarmBodiesAfterRefresh;
        startBackgroundRefresh();
    }

    synchronized String requestRefresh() {
        if (readOnly) {
            throw new IllegalStateException("The index is open read-only");
        }
        if (bodyPrewarmRunning.get()) {
            refreshAfterBodyPrewarm.set(true);
            return "{\"status\":\"queued_after_body_prewarm\"}";
        }
        bodyHydrationLock.lock();
        try {
            if (bodyPrewarmRunning.get()) {
                refreshAfterBodyPrewarm.set(true);
                return "{\"status\":\"queued_after_body_prewarm\"}";
            }
            if (!refreshRunning.compareAndSet(false, true)) {
                return "{\"status\":\"already_running\",\"processed\":" + processed.get() + "}";
            }
            try {
                refreshExecutor.submit(this::refreshReserved);
                return "{\"status\":\"started\"}";
            } catch (RuntimeException e) {
                refreshRunning.set(false);
                return "{\"status\":\"failed_to_start\"}";
            }
        } finally {
            bodyHydrationLock.unlock();
        }
    }

    void awaitRefresh() throws InterruptedException {
        synchronized (refreshMonitor) {
            while (refreshRunning.get()) {
                refreshMonitor.wait();
            }
        }
    }

    private String refreshReserved() {
        ThreadPoolExecutor classTasks = null;
        try {
            state = "indexing";
            lastStartedAt = Instant.now().toString();
            processed.set(0);
            classIndexCache.resetStats();
            classCacheHits = 0;
            classCacheMisses = 0;
            classCacheEnabled = classIndexCache.enabled();
            classCacheDirectory = classIndexCache.directory().toString();
            long started = System.nanoTime();
            Map<String, ExistingClass> existing = readExistingClasses();
            Set<String> seen = new HashSet<>();
            List<String> issues = new ArrayList<>();
            AtomicLong issueCount = new AtomicLong();
            Consumer<String> recordIssue = issue -> {
                issueCount.incrementAndGet();
                synchronized (issues) {
                    if (issues.size() < 250) issues.add(issue);
                }
            };
            AtomicLong skippedCount = new AtomicLong();
            AtomicLong foundCount = new AtomicLong();
            AtomicLong resourceSkipped = new AtomicLong();
            AtomicBoolean hadScanErrors = new AtomicBoolean();
            Map<String, String> existingResources = readResourceHashes();
            Set<String> seenResources = new HashSet<>();
            classTasks = newClassTaskExecutor(indexWorkerCount);
            ThreadPoolExecutor workers = classTasks;

            ArtifactScanner scanner = new ArtifactScanner(workspace, entry -> {
                foundCount.incrementAndGet();
                String id = entry.id();
                seen.add(id);
                try {
                    workers.execute(() -> {
                        try {
                            String hash = sha256(entry.bytes());
                            ExistingClass previous = existing.get(id);
                            if (previous != null && hash.equals(previous.hash())
                                    && entry.application() == previous.application()) {
                                skippedCount.incrementAndGet();
                                return;
                            }
                            BytecodeIndexer.IndexedClass indexed = bytecodeIndexer.indexSymbols(entry, hash);
                            writer.updateDocuments(new Term("classId", id), BytecodeIndexer.toDocuments(indexed, false));
                            if (indexed.error() != null) {
                                recordIssue.accept(id + ": " + indexed.error());
                                hadScanErrors.set(true);
                            }
                        } catch (Exception e) {
                            hadScanErrors.set(true);
                            recordIssue.accept(id + ": " + concise(e));
                        } finally {
                            processed.incrementAndGet();
                        }
                    });
                } catch (RejectedExecutionException e) {
                    hadScanErrors.set(true);
                    recordIssue.accept(id + ": class indexing task was rejected");
                    processed.incrementAndGet();
                }
            }, entry -> {
                seenResources.add(entry.id());
                try {
                    List<Document> resourceDocs = ResourceIndexer.toDocuments(entry);
                    Document resourceDoc = resourceDocs.getFirst();
                    String hash = resourceDoc.get("hash");
                    if (hash.equals(existingResources.get(entry.id()))) {
                        resourceSkipped.incrementAndGet();
                        processed.incrementAndGet();
                        return;
                    }
                    writer.updateDocuments(new Term("resourceId", entry.id()), resourceDocs);
                    processed.incrementAndGet();
                } catch (Exception e) {
                    hadScanErrors.set(true);
                    recordIssue.accept(entry.id() + ": " + concise(e));
                    processed.incrementAndGet();
                }
            }, issue -> {
                hadScanErrors.set(true);
                recordIssue.accept(issue);
            });
            ArtifactScanner.ScanSummary summary;
            try {
                summary = scanner.scan();
            } catch (IOException e) {
                hadScanErrors.set(true);
                recordIssue.accept("Workspace scan failed: " + concise(e));
                summary = new ArtifactScanner.ScanSummary(foundCount.get(), 0);
            } finally {
                workers.shutdown();
                while (!workers.awaitTermination(1, TimeUnit.MINUTES)) {
                    // Keep the refresh open until every accepted class has been indexed.
                }
            }

            if (!hadScanErrors.get()) {
                for (String staleId : existing.keySet()) {
                    if (!seen.contains(staleId)) {
                        writer.deleteDocuments(new Term("classId", staleId));
                    }
                }
                for (String staleId : existingResources.keySet()) {
                    if (!seenResources.contains(staleId)) {
                        writer.deleteDocuments(new Term("resourceId", staleId));
                    }
                }
            }
            writer.commit();
            classIndexCache.pruneIfNeeded();
            searchers.maybeRefreshBlocking();
            updateIndexDiagnostics();

            classesFound = summary.classesFound();
            classesSkipped = skippedCount.get();
            classesIndexed = countDocuments("class");
            methodsIndexed = countDocuments("method");
            classesWithGraphIndexed = countGraphIndexedClasses();
            graphIndexState = classesWithGraphIndexed == 0 ? "symbols_only"
                    : classesWithGraphIndexed >= classesIndexed ? "complete" : "partial";
            classesWithBodiesIndexed = countBodyIndexedClasses();
            bodyIndexState = classesWithBodiesIndexed == 0 ? "symbols_only"
                    : classesWithBodiesIndexed >= classesIndexed ? "complete" : "partial";
            updateBodyPrewarmAfterRefresh();
            resourcesIndexed = countDocuments("config") + countDocuments("template");
            resourcesSkipped = resourceSkipped.get();
            errors = issueCount.get();
            classCacheHits = classIndexCache.hits();
            classCacheMisses = classIndexCache.misses();
            synchronized (issues) {
                recentIssues = issues.stream().limit(25).toList();
            }
            refreshDurationMs = (System.nanoTime() - started) / 1_000_000;
            lastCompletedAt = Instant.now().toString();
            state = hadScanErrors.get() ? "completed_with_errors" : "ready";
            persistStatus();
            return statusJson();
        } catch (Exception e) {
            state = "failed";
            recentIssues = List.of(concise(e));
            errors++;
            classCacheHits = classIndexCache.hits();
            classCacheMisses = classIndexCache.misses();
            persistStatus();
            return statusJson();
        } finally {
            if (classTasks != null && !classTasks.isTerminated()) {
                classTasks.shutdownNow();
                boolean interrupted = false;
                while (!classTasks.isTerminated()) {
                    try {
                        classTasks.awaitTermination(1, TimeUnit.MINUTES);
                    } catch (InterruptedException e) {
                        interrupted = true;
                    }
                }
                if (interrupted) Thread.currentThread().interrupt();
            }
            refreshRunning.set(false);
            synchronized (refreshMonitor) {
                refreshMonitor.notifyAll();
            }
            if (autoPrewarmAfterRefresh && !state.equals("failed") && needsBodyPrewarm()) {
                requestBackgroundBodyPrewarm();
            }
        }
    }

    boolean needsBodyPrewarm() {
        return classesIndexed > classesWithBodiesIndexed;
    }

    private void updateBodyPrewarmAfterRefresh() {
        bodyPrewarmTargetScope = "all";
        bodyPrewarmTotal = classesIndexed;
        bodyPrewarmProcessed = classesWithBodiesIndexed;
        if (classesWithBodiesIndexed >= classesIndexed) {
            bodyPrewarmState = classesIndexed == 0 ? "not_started" : "complete";
            bodyPrewarmPhase = classesIndexed == 0 ? "idle" : "complete";
            if (classesIndexed > 0) bodyPrewarmCompletedAt = Instant.now().toString();
        } else {
            bodyPrewarmState = classesWithBodiesIndexed == 0 ? "not_started" : "partial";
            bodyPrewarmPhase = classesWithBodiesIndexed == 0 ? "idle" : "partial";
            bodyPrewarmCompletedAt = "";
        }
    }

    private void requestBackgroundBodyPrewarm() {
        if (!bodyPrewarmRunning.compareAndSet(false, true)) return;
        bodyPrewarmState = "scheduled";
        bodyPrewarmPhase = "application";
        bodyPrewarmTargetScope = "all";
        bodyPrewarmTotal = classesIndexed;
        bodyPrewarmProcessed = classesWithBodiesIndexed;
        bodyPrewarmStartedAt = Instant.now().toString();
        bodyPrewarmCompletedAt = "";
        bodyPrewarmIssue = "";
        persistStatus();
        try {
            refreshExecutor.submit(() -> {
                try (BodyPrewarmCoordinator.LockHandle ignored = BodyPrewarmCoordinator.acquire(workspace)) {
                    prewarmBodies();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    bodyPrewarmState = "interrupted";
                    bodyPrewarmPhase = "interrupted";
                    bodyPrewarmIssue = "Background body prewarm was interrupted";
                    bodyPrewarmCompletedAt = Instant.now().toString();
                    persistStatus();
                } catch (Exception e) {
                    bodyPrewarmState = "failed";
                    bodyPrewarmPhase = "failed";
                    bodyPrewarmIssue = concise(e);
                    bodyPrewarmCompletedAt = Instant.now().toString();
                    persistStatus();
                } finally {
                    bodyPrewarmRunning.set(false);
                    if (refreshAfterBodyPrewarm.getAndSet(false)) requestRefresh();
                }
            });
        } catch (RejectedExecutionException e) {
            bodyPrewarmRunning.set(false);
            bodyPrewarmState = "failed";
            bodyPrewarmPhase = "failed";
            bodyPrewarmIssue = "Could not schedule background body prewarm";
            bodyPrewarmCompletedAt = Instant.now().toString();
            persistStatus();
        }
    }

    String searchCode(String queryText, String mode, String scope, int limit, int offset,
                      boolean includeBodies) throws Exception {
        if (queryText == null || queryText.isBlank()) {
            throw new IllegalArgumentException("query is required");
        }
        if (queryText.length() > 4_096) throw new IllegalArgumentException("query is limited to 4096 characters");
        if (refreshRunning.get()) awaitRefresh();
        int safeLimit = Math.max(1, Math.min(MAX_PAGE_SIZE, limit));
        int safeOffset = Math.max(0, Math.min(MAX_OFFSET, offset));
        String normalizedMode = mode == null || mode.isBlank() ? "text" : mode.toLowerCase(java.util.Locale.ROOT);
        String normalizedScope = normalizeArtifactScope(scope);
        if (normalizedMode.equals("substring") || normalizedMode.equals("regex")) {
            if (queryText.codePointCount(0, queryText.length()) > 4_096) {
                throw new IllegalArgumentException("pattern is limited to 4096 characters");
            }
            String literal = normalizedMode.equals("substring") ? queryText : requiredRegexPrefix(queryText);
            if (trigrams(literal).isEmpty()) {
                throw new IllegalArgumentException("substring and regex searches need at least three literal characters");
            }
            if (normalizedMode.equals("regex")) Pattern.compile(queryText, Pattern.CASE_INSENSITIVE);
            if (includeBodies) ensureBodiesIndexed(normalizedScope);
            return searchCodePattern(queryText, normalizedMode, normalizedScope, safeLimit, safeOffset, includeBodies);
        }
        if (!normalizedMode.equals("text")) {
            throw new IllegalArgumentException("mode must be text, substring, or regex");
        }
        Query query = parseSearchQuery(queryText);
        if (includeBodies) ensureBodiesIndexed(normalizedScope);
        BooleanQuery.Builder codeOnly = new BooleanQuery.Builder();
        codeOnly.add(query, BooleanClause.Occur.MUST);
        codeOnly.add(new BooleanQuery.Builder()
                .add(new TermQuery(new Term("docType", "class")), BooleanClause.Occur.SHOULD)
                .add(new TermQuery(new Term("docType", "method")), BooleanClause.Occur.SHOULD)
                .setMinimumNumberShouldMatch(1).build(), BooleanClause.Occur.MUST);
        query = codeOnly.build();
        if (!normalizedScope.equals("all")) {
            BooleanQuery.Builder filtered = new BooleanQuery.Builder();
            filtered.add(query, BooleanClause.Occur.MUST);
            filtered.add(new TermQuery(new Term("application", normalizedScope.equals("application") ? "true" : "false")),
                    BooleanClause.Occur.MUST);
            query = filtered.build();
        }
        return runSearch(query, safeLimit, safeOffset, normalizedScope.equals("all"), normalizedScope, includeBodies);
    }

    private static String normalizeArtifactScope(String scope) {
        String normalized = scope == null || scope.isBlank() ? "all" : scope.toLowerCase(java.util.Locale.ROOT);
        if (!normalized.equals("all") && !normalized.equals("application") && !normalized.equals("dependency")) {
            throw new IllegalArgumentException("scope must be all, application, or dependency");
        }
        return normalized;
    }

    private String searchCodePattern(String input, String mode, String scope, int limit, int offset,
                                     boolean includeBodies) throws IOException {
        if (input.codePointCount(0, input.length()) > 4_096) {
            throw new IllegalArgumentException("pattern is limited to 4096 characters");
        }
        String literal = mode.equals("substring") ? input : requiredRegexPrefix(input);
        List<String> grams = trigrams(literal);
        if (grams.isEmpty()) {
            throw new IllegalArgumentException("substring and regex searches need at least three literal characters");
        }
        Query codeTypes = new BooleanQuery.Builder()
                .add(new TermQuery(new Term("docType", "class")), BooleanClause.Occur.SHOULD)
                .add(new TermQuery(new Term("docType", "method")), BooleanClause.Occur.SHOULD)
                .setMinimumNumberShouldMatch(1).build();
        BooleanQuery.Builder gramsQuery = new BooleanQuery.Builder();
        for (String gram : grams.stream().limit(1_000).toList()) {
            gramsQuery.add(new TermQuery(new Term("trigramContent", gram)), BooleanClause.Occur.MUST);
        }
        String normalizedScope = scope == null || scope.isBlank() ? "all" : scope.toLowerCase(java.util.Locale.ROOT);
        Query base = new BooleanQuery.Builder()
                .add(codeTypes, BooleanClause.Occur.MUST)
                .add(gramsQuery.build(), BooleanClause.Occur.MUST)
                .build();
        boolean appOnly = normalizedScope.equals("application");
        boolean dependencyOnly = normalizedScope.equals("dependency");
        if (!normalizedScope.equals("all") && !appOnly && !dependencyOnly) {
            throw new IllegalArgumentException("scope must be all, application, or dependency");
        }
        Pattern regex = mode.equals("regex") ? Pattern.compile(input, Pattern.CASE_INSENSITIVE) : null;
        String lowerInput = input.toLowerCase(java.util.Locale.ROOT);
        IndexSearcher searcher = searchers.acquire();
        try {
            List<org.apache.lucene.search.ScoreDoc> candidates = new ArrayList<>();
            List<Query> candidateQueries = new ArrayList<>();
            if (!dependencyOnly) candidateQueries.add(filtered(base, "true"));
            if (dependencyOnly) candidateQueries.add(filtered(base, "false"));
            else if (!appOnly) candidateQueries.add(filtered(base, "false"));
            int candidateLimit = 1_500;
            long candidateTotal = 0;
            boolean truncated = false;
            for (Query candidateQuery : candidateQueries) {
                TopDocs page = searcher.search(candidateQuery, candidateLimit + 1);
                candidateTotal += page.totalHits.value();
                int returned = Math.min(candidateLimit, page.scoreDocs.length);
                for (int i = 0; i < returned; i++) candidates.add(page.scoreDocs[i]);
                truncated |= page.scoreDocs.length > candidateLimit
                        || page.totalHits.relation() == org.apache.lucene.search.TotalHits.Relation.GREATER_THAN_OR_EQUAL_TO;
            }
            List<Map<String, Object>> matches = new ArrayList<>();
            for (var hit : candidates) {
                Document doc = searcher.storedFields().document(hit.doc);
                String content = doc.get("content");
                if (content == null || content.isBlank()) {
                    List<String> symbols = new ArrayList<>();
                    for (String field : List.of("className", "packageName", "methodName", "signature", "annotations")) {
                        java.util.Collections.addAll(symbols, doc.getValues(field));
                    }
                    content = String.join(" ", symbols);
                }
                boolean matchesPattern = regex == null
                        ? content.toLowerCase(java.util.Locale.ROOT).contains(lowerInput)
                        : regex.matcher(content).find();
                if (!matchesPattern) continue;
                Map<String, Object> result = new LinkedHashMap<>();
                result.put("kind", doc.get("docType"));
                result.put("className", doc.get("className"));
                result.put("methodName", doc.get("methodName"));
                result.put("signature", doc.get("signature"));
                result.put("artifact", doc.get("artifact"));
                result.put("entry", doc.get("entry"));
                result.put("application", Boolean.parseBoolean(doc.get("application")));
                result.put("preview", content.length() > 900 ? content.substring(0, 900) + "…" : content);
                matches.add(result);
            }
            int from = Math.min(offset, matches.size());
            int to = Math.min(from + limit, matches.size());
            Map<String, Object> response = new LinkedHashMap<>();
            response.put("mode", mode);
            response.put("query", input);
            response.put("totalHits", matches.size());
            response.put("candidateCount", candidateTotal);
            response.put("offset", offset);
            response.put("limit", limit);
            response.put("truncatedCandidates", truncated);
            response.put("bodyIndexState", bodyIndexState);
            response.put("graphIndexState", graphIndexState);
            response.put("classesWithBodiesIndexed", classesWithBodiesIndexed);
            appendBodySearchStatus(response, scope, includeBodies);
            response.put("results", matches.subList(from, to));
            return json(response);
        } finally {
            searchers.release(searcher);
        }
    }

    void prewarmBodies() throws Exception {
        stagedBodyPrewarm = true;
        bodyPrewarmRunning.set(true);
        bodyPrewarmState = "running";
        bodyPrewarmTargetScope = "all";
        bodyPrewarmPhase = "application";
        bodyPrewarmStartedAt = Instant.now().toString();
        bodyPrewarmCompletedAt = "";
        bodyPrewarmIssue = "";
        bodyPrewarmTotal = countDocuments("class");
        bodyPrewarmProcessed = countBodyIndexedClasses();
        persistStatus();
        try {
            bodyPrewarmPhase = "application_bodies";
            bodyPrewarmTargetScope = "application";
            persistStatus();
            ensureBodiesIndexed("application");

            bodyPrewarmRunning.set(true);
            bodyPrewarmState = "running";
            bodyPrewarmTargetScope = "all";
            bodyPrewarmPhase = "dependency_bodies";
            bodyPrewarmProcessed = countBodyIndexedClasses();
            persistStatus();
            ensureBodiesIndexed("dependency");

            classesIndexed = countDocuments("class");
            classesWithBodiesIndexed = countBodyIndexedClasses();
            updateBodyIndexState();
            boolean complete = classesWithBodiesIndexed >= classesIndexed;
            bodyPrewarmState = complete ? "complete" : "partial";
            bodyPrewarmTargetScope = "all";
            bodyPrewarmPhase = complete ? "complete" : "partial";
            bodyPrewarmProcessed = classesWithBodiesIndexed;
            bodyPrewarmCompletedAt = Instant.now().toString();
            persistStatus();
        } catch (Exception e) {
            bodyPrewarmState = "failed";
            bodyPrewarmPhase = "failed";
            bodyPrewarmIssue = concise(e);
            bodyPrewarmCompletedAt = Instant.now().toString();
            persistStatus();
            throw e;
        } finally {
            stagedBodyPrewarm = false;
            bodyPrewarmRunning.set(false);
            if (refreshAfterBodyPrewarm.getAndSet(false)) requestRefresh();
        }
    }

    private void ensureBodiesIndexed(String scope) throws Exception {
        if (readOnly) {
            if (countBodyIndexedClasses(scope) >= countClassesInScope(scope)) return;
            throw new IllegalStateException("Method-body index is incomplete for scope '" + scope
                    + "'; wait for background prewarm or retry with a writable CLI session");
        }
        if (countBodyIndexedClasses(scope) >= countClassesInScope(scope)) return;
        boolean requestQueuedRefresh = false;
        Exception hydrationFailure = null;
        bodyHydrationLock.lockInterruptibly();
        try {
            if (refreshRunning.get()) awaitRefresh();
            boolean prewarmAlreadyRunning = bodyPrewarmRunning.get();
            if (!prewarmAlreadyRunning) {
                bodyPrewarmRunning.set(true);
                bodyPrewarmState = "running";
                bodyPrewarmStartedAt = Instant.now().toString();
                bodyPrewarmCompletedAt = "";
                bodyPrewarmIssue = "";
            }
            try {
                ensureBodiesIndexedLocked(scope);
            } finally {
                if (!prewarmAlreadyRunning) {
                    bodyPrewarmRunning.set(false);
                    requestQueuedRefresh = refreshAfterBodyPrewarm.getAndSet(false);
                }
            }
        } catch (Exception e) {
            hydrationFailure = e;
        } finally {
            bodyHydrationLock.unlock();
        }
        if (requestQueuedRefresh) requestRefresh();
        if (hydrationFailure != null) throw hydrationFailure;
    }

    private void ensureBodiesIndexedLocked(String scope) throws Exception {
        classesIndexed = countDocuments("class");
        classesWithBodiesIndexed = countBodyIndexedClasses();
        bodyPrewarmTargetScope = stagedBodyPrewarm ? "all" : scope;
        bodyPrewarmTotal = stagedBodyPrewarm ? classesIndexed : countClassesInScope(scope);
        bodyPrewarmProcessed = stagedBodyPrewarm ? classesWithBodiesIndexed : countBodyIndexedClasses(scope);
        if (!bodyPrewarmRunning.get()) {
            bodyPrewarmRunning.set(true);
            bodyPrewarmState = "running";
            bodyPrewarmStartedAt = Instant.now().toString();
            bodyPrewarmCompletedAt = "";
            bodyPrewarmIssue = "";
        }
        try {
            if (countBodyIndexedClasses(scope) >= countClassesInScope(scope)) {
                updateBodyIndexState();
                bodyPrewarmState = stagedBodyPrewarm ? "running" : "complete";
                bodyPrewarmTargetScope = stagedBodyPrewarm ? "all" : scope;
                bodyPrewarmPhase = stagedBodyPrewarm
                        ? scope.equals("application") ? "application_complete" : "dependency_complete"
                        : "complete";
                bodyPrewarmProcessed = stagedBodyPrewarm
                        ? classesWithBodiesIndexed : countBodyIndexedClasses(scope);
                if (!stagedBodyPrewarm) bodyPrewarmCompletedAt = Instant.now().toString();
                persistStatus();
                return;
            }

            bodyIndexState = "indexing";
            AtomicLong hydrationErrors = new AtomicLong();
            List<String> hydrationIssues = java.util.Collections.synchronizedList(new ArrayList<>());
            AtomicLong progress = new AtomicLong(stagedBodyPrewarm
                    ? classesWithBodiesIndexed : countBodyIndexedClasses(scope));
            List<String> phases = scope.equals("all") ? List.of("application", "dependency") : List.of(scope);
            long totalClasses = bodyPrewarmTotal;
            persistStatus();
            for (String phase : phases) {
                bodyPrewarmPhase = phase + "_bodies";
                bodyPrewarmProcessed = progress.get();
                persistStatus();
                if (countBodyIndexedClasses(phase) < countClassesInScope(phase)) {
                    hydrateBodiesInScope(phase, progress, totalClasses, hydrationErrors, hydrationIssues);
                }
                writer.commit();
                searchers.maybeRefreshBlocking();
                classesWithBodiesIndexed = countBodyIndexedClasses();
                updateBodyIndexState();
                bodyPrewarmProcessed = Math.max(progress.get(), classesWithBodiesIndexed);
                persistStatus();
            }

            classesIndexed = countDocuments("class");
            classesWithBodiesIndexed = countBodyIndexedClasses();
            updateBodyIndexState();
            classesWithGraphIndexed = countGraphIndexedClasses();
            graphIndexState = classesWithGraphIndexed >= classesIndexed ? "complete" : "partial";
            classIndexCache.pruneIfNeeded();
            if (hydrationErrors.get() > 0) {
                List<String> issues = new ArrayList<>(recentIssues);
                issues.addAll(hydrationIssues);
                recentIssues = issues.stream().limit(25).toList();
                bodyPrewarmIssue = hydrationErrors.get() + " class body indexing error(s)";
            }
            boolean targetComplete = countBodyIndexedClasses(scope) >= countClassesInScope(scope);
            bodyPrewarmState = stagedBodyPrewarm ? "running" : targetComplete ? "complete" : "partial";
            bodyPrewarmTargetScope = stagedBodyPrewarm ? "all" : scope;
            bodyPrewarmPhase = stagedBodyPrewarm
                    ? scope.equals("application") ? (targetComplete ? "application_complete" : "application_partial")
                    : (targetComplete ? "dependency_complete" : "dependency_partial")
                    : targetComplete ? "complete" : "partial";
            bodyPrewarmProcessed = Math.max(progress.get(), countBodyIndexedClasses(scope));
            if (!stagedBodyPrewarm) bodyPrewarmCompletedAt = Instant.now().toString();
            persistStatus();
        } catch (Exception e) {
            bodyPrewarmState = "failed";
            bodyPrewarmPhase = "failed";
            bodyPrewarmIssue = concise(e);
            bodyPrewarmCompletedAt = Instant.now().toString();
            persistStatus();
            throw e;
        }
    }

    private void hydrateBodiesInScope(String scope, AtomicLong progress, long totalClasses,
                                      AtomicLong hydrationErrors, List<String> hydrationIssues) throws Exception {
        ThreadPoolExecutor workers = newClassTaskExecutor(indexWorkerCount);
        Query classQuery = classQueryInScope(scope);
        IndexSearcher searcher = searchers.acquire();
        try {
            org.apache.lucene.search.ScoreDoc after = null;
            while (true) {
                TopDocs page = searcher.searchAfter(after, classQuery, 1_000);
                if (page.scoreDocs.length == 0) break;
                for (var hit : page.scoreDocs) {
                    Document document = searcher.storedFields().document(hit.doc);
                    if ("true".equals(document.get("bodyIndexed"))) continue;
                    IndexedClassRef ref = new IndexedClassRef(document.get("classId"), document.get("artifact"),
                            document.get("entry"), document.get("hash"),
                            Boolean.parseBoolean(document.get("application")));
                    workers.execute(() -> {
                        try {
                            BytecodeIndexer.IndexedClass indexed = loadFullClass(ref);
                            writer.updateDocuments(new Term("classId", ref.classId()),
                                    BytecodeIndexer.toDocuments(indexed, true));
                        } catch (Exception e) {
                            hydrationErrors.incrementAndGet();
                            synchronized (hydrationIssues) {
                                if (hydrationIssues.size() < 25) {
                                    hydrationIssues.add(ref.classId() + ": " + concise(e));
                                }
                            }
                        } finally {
                            long completed = progress.incrementAndGet();
                            reportBodyPrewarmProgress(completed, totalClasses);
                        }
                    });
                }
                after = page.scoreDocs[page.scoreDocs.length - 1];
            }
        } finally {
            searchers.release(searcher);
            workers.shutdown();
            boolean interrupted = false;
            while (!workers.isTerminated()) {
                try {
                    workers.awaitTermination(1, TimeUnit.MINUTES);
                } catch (InterruptedException e) {
                    interrupted = true;
                    workers.shutdownNow();
                }
            }
            if (interrupted) {
                Thread.currentThread().interrupt();
                throw new InterruptedException("Method-body indexing was interrupted");
            }
        }
    }

    private void reportBodyPrewarmProgress(long processed, long total) {
        bodyPrewarmProcessed = processed;
        long now = System.nanoTime();
        long previous = lastBodyPrewarmPersistNanos.get();
        if (processed >= total || now - previous >= TimeUnit.SECONDS.toNanos(2)) {
            if (lastBodyPrewarmPersistNanos.compareAndSet(previous, now)) persistStatus();
        }
    }

    private void updateBodyIndexState() throws IOException {
        classesIndexed = countDocuments("class");
        classesWithBodiesIndexed = countBodyIndexedClasses();
        bodyIndexState = classesWithBodiesIndexed == 0 ? "symbols_only"
                : classesWithBodiesIndexed >= classesIndexed ? "complete" : "partial";
        decompilerFailures = countBodyDecompilationFailures("all");
    }

    private BytecodeIndexer.IndexedClass loadFullClass(IndexedClassRef ref) throws Exception {
        ArtifactScanner.ClassEntry cacheEntry = new ArtifactScanner.ClassEntry(ref.artifact(), ref.entry(),
                ref.application(), new byte[0]);
        BytecodeIndexer.IndexedClass cached = classIndexCache.get(ref.hash(), cacheEntry);
        if (cached != null && cached.bodyIndexed()) return cached;
        byte[] bytes = ArtifactScanner.readClassEntry(workspace, ref.artifact(), ref.entry());
        if (!ref.hash().equals(sha256(bytes))) {
            throw new IOException("Artifact changed since indexing; run `refresh` before hydrating method bodies");
        }
        ArtifactScanner.ClassEntry entry = new ArtifactScanner.ClassEntry(ref.artifact(), ref.entry(),
                ref.application(), bytes);
        return bytecodeIndexer.indexWithBodies(entry, ref.hash(), decompileWorkers, classIndexCache, cached);
    }

    private synchronized void ensureGraphIndexed() throws Exception {
        if (readOnly) {
            throw new IllegalStateException("Call-graph indexing requires a writable index; run the query through a writable session");
        }
        if (refreshRunning.get()) awaitRefresh();
        classesIndexed = countDocuments("class");
        classesWithGraphIndexed = countGraphIndexedClasses();
        if (classesWithGraphIndexed >= classesIndexed) {
            graphIndexState = classesIndexed == 0 ? "symbols_only" : "complete";
            return;
        }

        graphIndexState = "indexing";
        persistStatus();
        AtomicLong hydrationErrors = new AtomicLong();
        List<String> hydrationIssues = java.util.Collections.synchronizedList(new ArrayList<>());
        ThreadPoolExecutor workers = newClassTaskExecutor(indexWorkerCount);
        Query classQuery = new TermQuery(new Term("docType", "class"));
        IndexSearcher searcher = searchers.acquire();
        try {
            int count = searcher.count(classQuery);
            TopDocs docs = searcher.search(classQuery, Math.max(1, count));
            for (var hit : docs.scoreDocs) {
                Document document = searcher.storedFields().document(hit.doc);
                if ("true".equals(document.get("graphIndexed"))) continue;
                IndexedClassRef ref = new IndexedClassRef(document.get("classId"), document.get("artifact"),
                        document.get("entry"), document.get("hash"),
                        Boolean.parseBoolean(document.get("application")));
                workers.execute(() -> {
                    try {
                        BytecodeIndexer.IndexedClass indexed = loadGraphClass(ref);
                        writer.updateDocuments(new Term("classId", ref.classId()),
                                BytecodeIndexer.toDocuments(indexed, indexed.bodyIndexed()));
                    } catch (Exception e) {
                        hydrationErrors.incrementAndGet();
                        synchronized (hydrationIssues) {
                            if (hydrationIssues.size() < 25) {
                                hydrationIssues.add(ref.classId() + ": " + concise(e));
                            }
                        }
                    }
                });
            }
        } finally {
            searchers.release(searcher);
            workers.shutdown();
            while (!workers.awaitTermination(1, TimeUnit.MINUTES)) {
                // Wait for bounded tasks to finish before publishing the graph index.
            }
        }
        writer.commit();
        searchers.maybeRefreshBlocking();
        classesIndexed = countDocuments("class");
        classesWithGraphIndexed = countGraphIndexedClasses();
        graphIndexState = classesWithGraphIndexed >= classesIndexed ? "complete" : "partial";
        classesWithBodiesIndexed = countBodyIndexedClasses();
        bodyIndexState = classesWithBodiesIndexed == 0 ? "symbols_only"
                : classesWithBodiesIndexed >= classesIndexed ? "complete" : "partial";
        classIndexCache.pruneIfNeeded();
        if (hydrationErrors.get() > 0) {
            List<String> issues = new ArrayList<>(recentIssues);
            issues.addAll(hydrationIssues);
            recentIssues = issues.stream().limit(25).toList();
        }
        persistStatus();
    }

    private BytecodeIndexer.IndexedClass loadGraphClass(IndexedClassRef ref) throws Exception {
        ArtifactScanner.ClassEntry cacheEntry = new ArtifactScanner.ClassEntry(ref.artifact(), ref.entry(),
                ref.application(), new byte[0]);
        BytecodeIndexer.IndexedClass cached = classIndexCache.get(ref.hash(), cacheEntry);
        if (cached != null && cached.graphIndexed()) return cached;
        byte[] bytes = ArtifactScanner.readClassEntry(workspace, ref.artifact(), ref.entry());
        if (!ref.hash().equals(sha256(bytes))) {
            throw new IOException("Artifact changed since indexing; run `refresh` before hydrating call edges");
        }
        ArtifactScanner.ClassEntry entry = new ArtifactScanner.ClassEntry(ref.artifact(), ref.entry(),
                ref.application(), bytes);
        return bytecodeIndexer.indexGraph(entry, ref.hash(), classIndexCache, cached);
    }

    private record IndexedClassRef(String classId, String artifact, String entry, String hash, boolean application) {
    }

    private static List<String> trigrams(String input) {
        int[] codePoints = input.toLowerCase(java.util.Locale.ROOT).codePoints().toArray();
        Set<String> grams = new java.util.LinkedHashSet<>();
        for (int i = 0; i + 2 < codePoints.length; i++) {
            grams.add(new String(codePoints, i, 3));
        }
        return List.copyOf(grams);
    }

    private static String requiredRegexPrefix(String expression) {
        if (expression.contains("|")) {
            throw new IllegalArgumentException("regex alternation is not supported with bounded candidate filtering");
        }
        String value = expression.startsWith("(?i)") ? expression.substring(4) : expression;
        if (value.startsWith("^") ) value = value.substring(1);
        StringBuilder prefix = new StringBuilder();
        for (int i = 0; i < value.length();) {
            int cp = value.codePointAt(i);
            i += Character.charCount(cp);
            if (cp == '\\') {
                if (i >= value.length()) break;
                int escaped = value.codePointAt(i);
                i += Character.charCount(escaped);
                if (Character.isLetterOrDigit(escaped)) break;
                prefix.appendCodePoint(escaped);
                continue;
            }
            if (cp == '*' || cp == '?') {
                if (!prefix.isEmpty()) {
                    prefix.setLength(prefix.offsetByCodePoints(prefix.length(), -1));
                }
                break;
            }
            if (cp == '{') {
                int close = value.indexOf('}', i);
                if (close < 0 || value.substring(i, close).startsWith("0")) {
                    if (!prefix.isEmpty()) prefix.setLength(prefix.offsetByCodePoints(prefix.length(), -1));
                }
                break;
            }
            if (".+()[]$^".indexOf(cp) >= 0) break;
            prefix.appendCodePoint(cp);
        }
        if (prefix.codePointCount(0, prefix.length()) < 3) {
            throw new IllegalArgumentException("regex must start with at least three required literal characters");
        }
        return prefix.toString();
    }

    private static Analyzer createAnalyzer() {
        Analyzer ngrams = new Analyzer() {
            @Override
            protected TokenStreamComponents createComponents(String fieldName) {
                Tokenizer tokenizer = new NGramTokenizer(3, 3);
                return new TokenStreamComponents(tokenizer);
            }
        };
        return new PerFieldAnalyzerWrapper(new StandardAnalyzer(), Map.of("trigramContent", ngrams));
    }

    String searchConfig(String queryText, int limit, int offset) throws IOException {
        if (queryText == null || queryText.isBlank()) {
            throw new IllegalArgumentException("query is required");
        }
        if (queryText.length() > 4_096) throw new IllegalArgumentException("query is limited to 4096 characters");
        if (refreshRunning.get()) {
            try {
                awaitRefresh();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("Interrupted while waiting for symbol indexing", e);
            }
        }
        MultiFieldQueryParser parser = new MultiFieldQueryParser(new String[]{"path", "content", "artifact"}, analyzer,
                Map.of("path", 3.0f, "artifact", 2.0f, "content", 1.0f));
        Query parsed;
        try {
            parsed = parser.parse(queryText);
        } catch (org.apache.lucene.queryparser.classic.ParseException e) {
            try {
                parsed = parser.parse(MultiFieldQueryParser.escape(queryText));
            } catch (org.apache.lucene.queryparser.classic.ParseException impossible) {
                throw new IllegalArgumentException("Could not parse configuration query", impossible);
            }
        }
        BooleanQuery query = new BooleanQuery.Builder()
                .add(parsed, BooleanClause.Occur.MUST)
                .add(new BooleanQuery.Builder()
                        .add(new TermQuery(new Term("docType", "config")), BooleanClause.Occur.SHOULD)
                        .add(new TermQuery(new Term("docType", "template")), BooleanClause.Occur.SHOULD)
                        .setMinimumNumberShouldMatch(1).build(), BooleanClause.Occur.MUST)
                .build();
        return runSearch(query, Math.max(1, Math.min(MAX_PAGE_SIZE, limit)),
                Math.max(0, Math.min(MAX_OFFSET, offset)), true, null, false);
    }

    String getMethod(String className, String methodName, String descriptor, String artifact) throws Exception {
        if (className == null || className.isBlank() || methodName == null || methodName.isBlank()) {
            throw new IllegalArgumentException("className and methodName are required");
        }
        if (className.length() > 1_000 || methodName.length() > 256
                || (descriptor != null && descriptor.length() > 2_000)
                || (artifact != null && artifact.length() > 4_096)) {
            throw new IllegalArgumentException("method lookup fields exceed the supported length");
        }
        if (refreshRunning.get()) awaitRefresh();
        BooleanQuery.Builder builder = new BooleanQuery.Builder();
        builder.add(new TermQuery(new Term("docType", "method")), BooleanClause.Occur.MUST);
        builder.add(new TermQuery(new Term("classNameExact", className)), BooleanClause.Occur.MUST);
        builder.add(new TermQuery(new Term("methodNameExact", methodName)), BooleanClause.Occur.MUST);
        if (descriptor != null && !descriptor.isBlank()) {
            builder.add(new TermQuery(new Term("descriptor", descriptor)), BooleanClause.Occur.MUST);
        }
        if (artifact != null && !artifact.isBlank()) {
            builder.add(new TermQuery(new Term("artifact", artifact)), BooleanClause.Occur.MUST);
        }
        IndexSearcher searcher = searchers.acquire();
        List<Document> candidates = new ArrayList<>();
        long totalHits;
        try {
            TopDocs app = searcher.search(filtered(builder.build(), "true"), 20);
            TopDocs dependencies = searcher.search(filtered(builder.build(), "false"), 20);
            totalHits = app.totalHits.value() + dependencies.totalHits.value();
            for (var hit : app.scoreDocs) candidates.add(searcher.storedFields().document(hit.doc));
            for (var hit : dependencies.scoreDocs) {
                if (candidates.size() >= 20) break;
                candidates.add(searcher.storedFields().document(hit.doc));
            }
        } finally {
            searchers.release(searcher);
        }
        List<Map<String, Object>> results = new ArrayList<>();
        Map<String, BytecodeIndexer.IndexedClass> hydrated = new HashMap<>();
        for (Document document : candidates) {
            String classId = document.get("classId");
            BytecodeIndexer.IndexedClass indexed = hydrated.get(classId);
            if (indexed == null) {
                indexed = loadFullClass(document);
                hydrated.put(classId, indexed);
            }
            String expectedName = document.get("methodName");
            String expectedDescriptor = document.get("descriptor");
            BytecodeIndexer.MethodRecord method = indexed.methodRecords().stream()
                    .filter(record -> record.name().equals(expectedName)
                            && record.descriptor().equals(expectedDescriptor))
                    .findFirst().orElse(null);
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("className", document.get("className"));
            result.put("methodName", expectedName);
            result.put("signature", document.get("signature"));
            result.put("descriptor", expectedDescriptor);
            result.put("artifact", document.get("artifact"));
            result.put("entry", document.get("entry"));
            result.put("application", Boolean.parseBoolean(document.get("application")));
            result.put("bodyIndexedOnDemand", true);
            String source = method == null ? "" : method.source();
            result.put("source", source.length() > 20_000
                    ? source.substring(0, 20_000) + "\n/* truncated at 20000 characters */" : source);
            results.add(result);
        }
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("className", className);
        response.put("methodName", methodName);
        response.put("totalHits", totalHits);
        response.put("results", results);
        return json(response);
    }

    String getClassSource(String className, String artifact, String entry, int startLine, int endLine) throws Exception {
        if ((className == null || className.isBlank())
                && ((artifact == null || artifact.isBlank()) || (entry == null || entry.isBlank()))) {
            throw new IllegalArgumentException("className or an exact artifact and entry pair is required");
        }
        if ((className != null && className.length() > 1_000) || (artifact != null && artifact.length() > 4_096)) {
            throw new IllegalArgumentException("class lookup fields exceed the supported length");
        }
        if (refreshRunning.get()) awaitRefresh();
        BooleanQuery.Builder builder = new BooleanQuery.Builder();
        builder.add(new TermQuery(new Term("docType", "class")), BooleanClause.Occur.MUST);
        if (className != null && !className.isBlank()) {
            builder.add(new TermQuery(new Term("classNameExact", className)), BooleanClause.Occur.MUST);
        }
        if (artifact != null && !artifact.isBlank()) {
            builder.add(new TermQuery(new Term("artifact", artifact)), BooleanClause.Occur.MUST);
        }
        if (entry != null && !entry.isBlank()) {
            builder.add(new TermQuery(new Term("entry", entry)), BooleanClause.Occur.MUST);
        }

        IndexSearcher searcher = searchers.acquire();
        List<Document> candidates = new ArrayList<>();
        long totalHits;
        try {
            TopDocs app = searcher.search(filtered(builder.build(), "true"), 20);
            TopDocs dependencies = searcher.search(filtered(builder.build(), "false"), 20);
            totalHits = app.totalHits.value() + dependencies.totalHits.value();
            for (var hit : app.scoreDocs) candidates.add(searcher.storedFields().document(hit.doc));
            for (var hit : dependencies.scoreDocs) {
                if (candidates.size() >= 20) break;
                candidates.add(searcher.storedFields().document(hit.doc));
            }
        } finally {
            searchers.release(searcher);
        }

        int safeStart = Math.max(1, startLine);
        int safeEnd = endLine <= 0 ? safeStart + 199 : Math.max(safeStart, endLine);
        safeEnd = Math.min(safeEnd, safeStart + 299);
        List<Map<String, Object>> results = new ArrayList<>();
        Map<String, BytecodeIndexer.IndexedClass> hydrated = new HashMap<>();
        for (Document document : candidates) {
            String classId = document.get("classId");
            BytecodeIndexer.IndexedClass indexed = hydrated.get(classId);
            if (indexed == null) {
                indexed = loadFullClass(document);
                hydrated.put(classId, indexed);
            }
            String source = indexed.source();
            String[] lines = source.split("\\R", -1);
            int first = Math.min(safeStart, Math.max(1, lines.length));
            int last = Math.min(safeEnd, lines.length);
            StringBuilder snippet = new StringBuilder();
            for (int line = first; line <= last; line++) {
                String value = lines[line - 1];
                if (snippet.length() + value.length() + 1 > 45_000) break;
                if (snippet.length() > 0) snippet.append('\n');
                snippet.append(value);
            }
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("className", document.get("className"));
            result.put("artifact", document.get("artifact"));
            result.put("entry", document.get("entry"));
            result.put("application", Boolean.parseBoolean(document.get("application")));
            result.put("sha256", document.get("hash"));
            result.put("sourceLineStart", first);
            result.put("sourceLineEnd", first + snippet.toString().split("\\R", -1).length - 1);
            result.put("totalLines", lines.length);
            result.put("source", snippet.toString());
            results.add(result);
        }
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("className", className);
        response.put("totalHits", totalHits);
        response.put("results", results);
        return json(response);
    }

    String listClasses(int limit, int offset, String scope) throws IOException {
        if (refreshRunning.get()) {
            try {
                awaitRefresh();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("Interrupted while waiting for symbol indexing", e);
            }
        }
        int safeLimit = Math.max(1, Math.min(MAX_PAGE_SIZE, limit));
        int safeOffset = Math.max(0, Math.min(50_000, offset));
        String normalizedScope = scope == null || scope.isBlank() ? "all" : scope.trim().toLowerCase(Locale.ROOT);
        if (!normalizedScope.equals("all") && !normalizedScope.equals("application")
                && !normalizedScope.equals("dependency")) {
            throw new IllegalArgumentException("scope must be all, application, or dependency");
        }
        IndexSearcher searcher = searchers.acquire();
        List<Document> documents = new ArrayList<>();
        long total;
        try {
            BooleanQuery.Builder queryBuilder = new BooleanQuery.Builder();
            queryBuilder.add(new TermQuery(new Term("docType", "class")), BooleanClause.Occur.MUST);
            if (!normalizedScope.equals("all")) {
                queryBuilder.add(new TermQuery(new Term("application", Boolean.toString(normalizedScope.equals("application")))),
                        BooleanClause.Occur.MUST);
            }
            Query query = queryBuilder.build();
            total = searcher.count(query);
            TopDocs hits = searcher.search(query, (int) Math.max(1, Math.min(total, 50_000)));
            for (var hit : hits.scoreDocs) documents.add(searcher.storedFields().document(hit.doc));
        } finally {
            searchers.release(searcher);
        }
        documents.sort(Comparator
                .comparing((Document document) -> valueOrEmpty(document.get("className")))
                .thenComparing(document -> valueOrEmpty(document.get("artifact")))
                .thenComparing(document -> valueOrEmpty(document.get("entry"))));
        int from = Math.min(safeOffset, documents.size());
        int to = Math.min(from + safeLimit, documents.size());
        List<Map<String, Object>> classes = new ArrayList<>(to - from);
        for (Document document : documents.subList(from, to)) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("className", document.get("className"));
            item.put("artifact", document.get("artifact"));
            item.put("entry", document.get("entry"));
            item.put("application", Boolean.parseBoolean(document.get("application")));
            item.put("sha256", document.get("hash"));
            item.put("sizeBytes", parseLongOrZero(document.get("byteSize")));
            classes.add(item);
        }
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("total", total);
        response.put("offset", safeOffset);
        response.put("limit", safeLimit);
        response.put("scope", normalizedScope);
        response.put("truncated", total > documents.size());
        response.put("classes", classes);
        return json(response);
    }

    private static String valueOrEmpty(String value) {
        return value == null ? "" : value;
    }

    private static long parseLongOrZero(String value) {
        if (value == null || value.isBlank()) return 0;
        try {
            return Long.parseLong(value);
        } catch (NumberFormatException ignored) {
            return 0;
        }
    }

    private BytecodeIndexer.IndexedClass loadFullClass(Document document) throws Exception {
        String artifact = document.get("artifact");
        String entryName = document.get("entry");
        String hash = document.get("hash");
        boolean application = Boolean.parseBoolean(document.get("application"));
        ArtifactScanner.ClassEntry cacheEntry = new ArtifactScanner.ClassEntry(artifact, entryName, application,
                new byte[0]);
        BytecodeIndexer.IndexedClass cached = classIndexCache.get(hash, cacheEntry);
        if (cached != null && cached.bodyIndexed()) return cached;
        byte[] bytes = ArtifactScanner.readClassEntry(workspace, artifact, entryName);
        if (!hash.equals(sha256(bytes))) {
            throw new IOException("Artifact changed since indexing; run `refresh` before retrieving method bodies");
        }
        ArtifactScanner.ClassEntry entry = new ArtifactScanner.ClassEntry(artifact, entryName, application, bytes);
        return bytecodeIndexer.indexWithBodies(entry, hash, decompileWorkers, classIndexCache, cached);
    }

    String listWebEndpoints(String httpMethod, String pathContains, int limit, int offset) throws IOException {
        if (pathContains != null && pathContains.length() > 1_000) {
            throw new IllegalArgumentException("pathContains is limited to 1000 characters");
        }
        if (refreshRunning.get()) {
            try {
                awaitRefresh();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("Interrupted while waiting for symbol indexing", e);
            }
        }
        int safeLimit = Math.max(1, Math.min(MAX_PAGE_SIZE, limit));
        int safeOffset = Math.max(0, Math.min(MAX_OFFSET, offset));
        BooleanQuery.Builder builder = new BooleanQuery.Builder()
                .add(new BooleanQuery.Builder()
                        .add(new TermQuery(new Term("docType", "class")), BooleanClause.Occur.SHOULD)
                        .add(new TermQuery(new Term("docType", "endpoint")), BooleanClause.Occur.SHOULD)
                        .setMinimumNumberShouldMatch(1).build(), BooleanClause.Occur.MUST)
                .add(new FieldExistsQuery("endpointRoute"), BooleanClause.Occur.MUST);
        if (httpMethod != null && !httpMethod.isBlank()) {
            builder.add(new TermQuery(new Term("httpMethod", httpMethod.toUpperCase(java.util.Locale.ROOT))),
                    BooleanClause.Occur.MUST);
        }
        IndexSearcher searcher = searchers.acquire();
        try {
            TopDocs docs = searcher.search(builder.build(), 20_000);
            List<Map<String, Object>> endpoints = new ArrayList<>();
            for (var hit : docs.scoreDocs) {
                Document doc = searcher.storedFields().document(hit.doc);
                String[] routes = doc.getValues("endpointRoute");
                String[] methods = doc.getValues("httpMethod");
                String[] handlers = doc.getValues("endpointHandler");
                for (int i = 0; i < routes.length; i++) {
                    if (pathContains != null && !pathContains.isBlank()
                            && !routes[i].toLowerCase(java.util.Locale.ROOT)
                                    .contains(pathContains.toLowerCase(java.util.Locale.ROOT))) {
                        continue;
                    }
                    Map<String, Object> item = new LinkedHashMap<>();
                    item.put("route", routes[i]);
                    item.put("httpMethod", i < methods.length ? methods[i] : "ANY");
                    item.put("className", doc.get("className"));
                    item.put("handler", i < handlers.length ? handlers[i] : "");
                    item.put("artifact", doc.get("artifact"));
                    item.put("entry", doc.get("entry"));
                    item.put("application", Boolean.parseBoolean(doc.get("application")));
                    endpoints.add(item);
                }
            }
            endpoints.sort(Comparator.<Map<String, Object>, Boolean>comparing(item ->
                            Boolean.TRUE.equals(item.get("application"))).reversed()
                    .thenComparing(item -> String.valueOf(item.get("route"))));
            int from = Math.min(safeOffset, endpoints.size());
            int to = Math.min(from + safeLimit, endpoints.size());
            Map<String, Object> response = new LinkedHashMap<>();
            response.put("totalHits", endpoints.size());
            response.put("offset", safeOffset);
            response.put("limit", safeLimit);
            response.put("results", endpoints.subList(from, to));
            if (docs.scoreDocs.length == 20_000) {
                response.put("truncatedScan", true);
            }
            return json(response);
        } finally {
            searchers.release(searcher);
        }
    }

    String findCallers(String className, String methodName, String descriptor, int depth, int limit, int offset)
            throws Exception {
        ensureGraphIndexed();
        return walkCallGraph(className, methodName, descriptor, depth, limit, offset, true);
    }

    String findCallees(String className, String methodName, String descriptor, int depth, int limit, int offset)
            throws Exception {
        ensureGraphIndexed();
        return walkCallGraph(className, methodName, descriptor, depth, limit, offset, false);
    }

    private String walkCallGraph(String className, String methodName, String descriptor, int depth, int limit,
                                 int offset, boolean reverse) throws IOException {
        if (className == null || className.isBlank() || methodName == null || methodName.isBlank()) {
            throw new IllegalArgumentException("className and methodName are required");
        }
        if (className.length() > 1_000 || methodName.length() > 256
                || (descriptor != null && descriptor.length() > 2_000)) {
            throw new IllegalArgumentException("method lookup fields exceed the supported length");
        }
        int safeDepth = Math.max(1, Math.min(5, depth));
        int safeLimit = Math.max(1, Math.min(MAX_PAGE_SIZE, limit));
        int safeOffset = Math.max(0, Math.min(MAX_OFFSET, offset));
        String normalizedClass = className.replace('/', '.');
        IndexSearcher searcher = searchers.acquire();
        try {
            List<Document> seeds = findMethods(searcher, normalizedClass, methodName, descriptor);
            Set<String> frontier = new java.util.LinkedHashSet<>();
            if (seeds.isEmpty() && descriptor != null && !descriptor.isBlank()) {
                frontier.add(normalizedClass + "#" + methodName + descriptor);
            } else {
                seeds.forEach(doc -> frontier.add(doc.get("methodKey")));
            }
            List<Map<String, Object>> edges = reverse
                    ? reverseWalk(searcher, seeds, frontier, safeDepth)
                    : forwardWalk(searcher, seeds, safeDepth);
            Map<String, Object> response = new LinkedHashMap<>();
            response.put("direction", reverse ? "callers" : "callees");
            response.put("depth", safeDepth);
            response.put("totalHits", edges.size());
            response.put("offset", safeOffset);
            response.put("limit", safeLimit);
            int from = Math.min(safeOffset, edges.size());
            int to = Math.min(from + safeLimit, edges.size());
            response.put("results", edges.subList(from, to));
            response.put("truncated", edges.size() >= 5_000);
            if (seeds.isEmpty()) response.put("warning", "The requested method is not indexed; results use the symbolic method key.");
            return json(response);
        } finally {
            searchers.release(searcher);
        }
    }

    private List<Map<String, Object>> forwardWalk(IndexSearcher searcher, List<Document> seeds, int maxDepth)
            throws IOException {
        List<Map<String, Object>> edges = new ArrayList<>();
        Set<String> emitted = new HashSet<>();
        Set<String> visited = new HashSet<>();
        Map<String, List<Document>> methodCache = new HashMap<>();
        Map<String, List<String>> subtypeCache = new HashMap<>();
        List<Document> frontier = new ArrayList<>(seeds);
        seeds.forEach(doc -> visited.add(doc.get("recordId")));
        for (int level = 1; level <= maxDepth && !frontier.isEmpty() && edges.size() < 5_000; level++) {
            List<Document> next = new ArrayList<>();
            for (Document caller : frontier) {
                String from = caller.get("methodKey");
                if (from == null) continue;
                String[] targets = caller.getValues("callTarget");
                String[] kinds = caller.getValues("callKind");
                for (int i = 0; i < targets.length && edges.size() < 5_000; i++) {
                    MethodRef ref = parseMethodRef(targets[i]);
                    if (ref == null) continue;
                    String kind = i < kinds.length ? kinds[i] : "virtual";
                    List<Document> resolved = cachedMethods(searcher, methodCache, ref.owner(), ref.name(), ref.descriptor());
                    if (resolved.isEmpty()) {
                        addEdge(edges, emitted, edge(from, targets[i], "direct", kind, level, caller, null));
                    } else {
                        for (Document callee : resolved) {
                            addEdge(edges, emitted, edge(from, callee.get("methodKey"), "direct", kind, level, caller, callee));
                            if (visited.add(callee.get("recordId"))) next.add(callee);
                        }
                    }
                    if (kind.equals("virtual") || kind.equals("interface")) {
                        List<String> subtypes = subtypeCache.get(ref.owner());
                        if (subtypes == null) {
                            subtypes = findSubtypes(searcher, ref.owner());
                            subtypeCache.put(ref.owner(), subtypes);
                        }
                        for (String subtype : subtypes) {
                            if (subtype.equals(ref.owner())) continue;
                            for (Document possible : cachedMethods(searcher, methodCache, subtype, ref.name(), ref.descriptor())) {
                                if (Boolean.parseBoolean(possible.get("interfaceClass"))
                                        || Boolean.parseBoolean(possible.get("abstractClass"))) {
                                    continue;
                                }
                                addEdge(edges, emitted, edge(from, possible.get("methodKey"), "cha_possible", kind,
                                        level, caller, possible));
                                if (visited.add(possible.get("recordId"))) next.add(possible);
                                if (edges.size() >= 5_000) break;
                            }
                            if (edges.size() >= 5_000) break;
                        }
                    }
                }
            }
            frontier = next;
        }
        return edges;
    }

    private List<Map<String, Object>> reverseWalk(IndexSearcher searcher, List<Document> seedDocuments,
                                                   Set<String> seeds, int maxDepth)
            throws IOException {
        List<Map<String, Object>> edges = new ArrayList<>();
        Set<String> emitted = new HashSet<>();
        Set<String> visited = new HashSet<>();
        Map<String, List<String>> ancestorCache = new HashMap<>();
        Map<String, Document> knownMethods = new HashMap<>();
        seedDocuments.forEach(doc -> knownMethods.putIfAbsent(doc.get("methodKey"), doc));
        Set<String> frontier = new java.util.LinkedHashSet<>(seeds);
        for (int level = 1; level <= maxDepth && !frontier.isEmpty() && edges.size() < 5_000; level++) {
            Map<String, String> targets = new LinkedHashMap<>();
            for (String key : frontier) {
                targets.put(key, key);
                MethodRef ref = parseMethodRef(key);
                if (ref != null) {
                    List<String> ancestors = ancestorCache.get(ref.owner());
                    if (ancestors == null) {
                        ancestors = findAncestors(searcher, ref.owner());
                        ancestorCache.put(ref.owner(), ancestors);
                    }
                    for (String ancestor : ancestors) {
                        String ancestorKey = ancestor + "#" + ref.name() + ref.descriptor();
                        targets.put(ancestorKey, key);
                    }
                }
            }
            Query query = new BooleanQuery.Builder()
                    .add(new TermQuery(new Term("docType", "method")), BooleanClause.Occur.MUST)
                    .add(termSetQuery("callTarget", targets.keySet()), BooleanClause.Occur.MUST)
                    .build();
            TopDocs callers = searcher.search(query, 2_000);
            Set<String> next = new java.util.LinkedHashSet<>();
            for (var hit : callers.scoreDocs) {
                Document caller = searcher.storedFields().document(hit.doc);
                String[] calls = caller.getValues("callTarget");
                String[] kinds = caller.getValues("callKind");
                String from = caller.get("methodKey");
                for (int i = 0; i < calls.length; i++) {
                    String destination = targets.get(calls[i]);
                    if (destination == null) continue;
                    String relation = calls[i].equals(destination) ? "direct" : "cha_possible";
                    String kind = i < kinds.length ? kinds[i] : "virtual";
                    addEdge(edges, emitted, edge(from, destination, relation, kind, level, caller,
                            knownMethods.get(destination)));
                }
                if (from != null && visited.add(caller.get("recordId"))) {
                    knownMethods.putIfAbsent(from, caller);
                    next.add(from);
                }
                if (edges.size() >= 5_000) break;
            }
            frontier = next;
        }
        return edges;
    }

    private List<Document> findMethods(IndexSearcher searcher, String className, String methodName, String descriptor)
            throws IOException {
        BooleanQuery.Builder query = new BooleanQuery.Builder()
                .add(new TermQuery(new Term("docType", "method")), BooleanClause.Occur.MUST)
                .add(new TermQuery(new Term("classNameExact", className)), BooleanClause.Occur.MUST)
                .add(new TermQuery(new Term("methodNameExact", methodName)), BooleanClause.Occur.MUST);
        if (descriptor != null && !descriptor.isBlank()) {
            query.add(new TermQuery(new Term("descriptor", descriptor)), BooleanClause.Occur.MUST);
        }
        TopDocs docs = searcher.search(query.build(), 100);
        List<Document> result = new ArrayList<>();
        for (var hit : docs.scoreDocs) result.add(searcher.storedFields().document(hit.doc));
        return result;
    }

    private List<Document> cachedMethods(IndexSearcher searcher, Map<String, List<Document>> cache,
                                         String className, String methodName, String descriptor) throws IOException {
        String key = className + "#" + methodName + descriptor;
        List<Document> result = cache.get(key);
        if (result == null) {
            result = findMethods(searcher, className, methodName, descriptor);
            cache.put(key, result);
        }
        return result;
    }

    private List<String> findSubtypes(IndexSearcher searcher, String parent) throws IOException {
        Set<String> found = new java.util.LinkedHashSet<>();
        Set<String> frontier = Set.of(parent);
        while (!frontier.isEmpty() && found.size() < 5_000) {
            Query parents = new BooleanQuery.Builder()
                    .add(termSetQuery("superName", frontier), BooleanClause.Occur.SHOULD)
                    .add(termSetQuery("interfaceName", frontier), BooleanClause.Occur.SHOULD)
                    .setMinimumNumberShouldMatch(1).build();
            Query query = new BooleanQuery.Builder()
                    .add(new TermQuery(new Term("docType", "class")), BooleanClause.Occur.MUST)
                    .add(parents, BooleanClause.Occur.MUST).build();
            TopDocs docs = searcher.search(query, 5_000);
            Set<String> next = new java.util.LinkedHashSet<>();
            for (var hit : docs.scoreDocs) {
                Document doc = searcher.storedFields().document(hit.doc);
                String name = doc.get("className");
                if (name != null && !name.equals(parent) && found.add(name)) next.add(name);
            }
            frontier = next;
        }
        return List.copyOf(found);
    }

    private List<String> findAncestors(IndexSearcher searcher, String child) throws IOException {
        Set<String> found = new java.util.LinkedHashSet<>();
        Set<String> frontier = Set.of(child);
        while (!frontier.isEmpty() && found.size() < 500) {
            Query query = new BooleanQuery.Builder()
                    .add(new TermQuery(new Term("docType", "class")), BooleanClause.Occur.MUST)
                    .add(termSetQuery("classNameExact", frontier), BooleanClause.Occur.MUST)
                    .build();
            TopDocs docs = searcher.search(query, 100);
            Set<String> next = new java.util.LinkedHashSet<>();
            for (var hit : docs.scoreDocs) {
                Document doc = searcher.storedFields().document(hit.doc);
                String superName = doc.get("superName");
                if (superName != null && found.add(superName)) next.add(superName);
                for (String interfaceName : doc.getValues("interfaceName")) {
                    if (found.add(interfaceName)) next.add(interfaceName);
                }
            }
            frontier = next;
        }
        return List.copyOf(found);
    }

    private static Query termSetQuery(String field, Iterable<String> terms) {
        List<BytesRef> encoded = new ArrayList<>();
        for (String term : terms) encoded.add(new BytesRef(term));
        return new TermInSetQuery(field, encoded);
    }

    private static MethodRef parseMethodRef(String key) {
        int separator = key.indexOf('#');
        int descriptorStart = key.indexOf('(', separator + 1);
        if (separator < 1 || descriptorStart < 0) return null;
        return new MethodRef(key.substring(0, separator), key.substring(separator + 1, descriptorStart),
                key.substring(descriptorStart));
    }

    private static Map<String, Object> edge(String from, String to, String relation, String dispatch,
                                             int depth, Document source, Document target) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("from", from);
        result.put("to", to);
        result.put("relation", relation);
        result.put("dispatch", dispatch);
        result.put("depth", depth);
        result.put("fromArtifact", source.get("artifact"));
        if (target != null) {
            result.put("resolved", true);
            result.put("toArtifact", target.get("artifact"));
        } else {
            result.put("resolved", false);
        }
        return result;
    }

    private static void addEdge(List<Map<String, Object>> edges, Set<String> emitted, Map<String, Object> edge) {
        String key = edge.get("from") + "->" + edge.get("to") + ":" + edge.get("relation") + ":"
                + edge.get("depth") + ":" + edge.get("fromArtifact") + ":" + edge.get("toArtifact");
        if (emitted.add(key)) edges.add(edge);
    }

    private record MethodRef(String owner, String name, String descriptor) {
    }

    String statusJson() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("workspace", workspace.toString());
        status.put("indexDirectory", indexHome.toString());
        status.put("state", state);
        status.put("indexWorkers", indexWorkerCount);
        status.put("luceneRamBufferMb", luceneRamBufferMb);
        status.put("classCacheEnabled", classCacheEnabled);
        status.put("classCacheDirectory", classCacheDirectory);
        status.put("classCacheHits", classCacheHits);
        status.put("classCacheMisses", classCacheMisses);
        status.put("refreshRunning", refreshRunning.get());
        status.put("lastStartedAt", lastStartedAt);
        status.put("lastCompletedAt", lastCompletedAt);
        status.put("classesFound", classesFound);
        status.put("classesIndexed", classesIndexed);
        status.put("methodsIndexed", methodsIndexed);
        status.put("classesWithGraphIndexed", classesWithGraphIndexed);
        status.put("graphIndexState", graphIndexState);
        status.put("graphIndexComplete", classesIndexed > 0 && classesWithGraphIndexed >= classesIndexed);
        status.put("classesWithBodiesIndexed", classesWithBodiesIndexed);
        status.put("bodyIndexState", bodyIndexState);
        status.put("bodyIndexComplete", classesIndexed > 0 && classesWithBodiesIndexed >= classesIndexed);
        status.put("bodyPrewarmState", bodyPrewarmState);
        status.put("bodyPrewarmRunning", bodyPrewarmRunning.get());
        status.put("bodyPrewarmPhase", bodyPrewarmPhase);
        status.put("bodyPrewarmTargetScope", bodyPrewarmTargetScope);
        status.put("bodyPrewarmProcessed", bodyPrewarmProcessed);
        status.put("bodyPrewarmTotal", bodyPrewarmTotal);
        status.put("bodyPrewarmProgressPercent", bodyPrewarmTotal == 0
                ? bodyPrewarmState.equals("complete") ? 100 : 0
                : Math.min(100, Math.round(bodyPrewarmProcessed * 100.0 / bodyPrewarmTotal)));
        status.put("bodyPrewarmStartedAt", bodyPrewarmStartedAt);
        status.put("bodyPrewarmCompletedAt", bodyPrewarmCompletedAt);
        status.put("bodyPrewarmIssue", bodyPrewarmIssue);
        status.put("resourcesIndexed", resourcesIndexed);
        status.put("missingDependencyTypes", missingDependencyTypes);
        status.put("missingDependencyExamples", missingDependencyExamples);
        status.put("unsupportedClassFiles", unsupportedClassFiles);
        status.put("classParseErrors", classParseErrors);
        status.put("decompilerFailures", decompilerFailures);
        status.put("unchangedClassesSkipped", classesSkipped);
        status.put("unchangedResourcesSkipped", resourcesSkipped);
        status.put("processed", processed.get());
        status.put("errors", errors);
        status.put("refreshDurationMs", refreshDurationMs);
        status.put("recentIssues", recentIssues);
        return json(status);
    }

    private Query parseSearchQuery(String text) throws IOException {
        String[] fields = {"className", "methodName", "packageName", "signature", "annotations", "content"};
        Map<String, Float> boosts = Map.of("className", 4.0f, "methodName", 4.0f,
                "packageName", 1.5f, "signature", 2.5f, "annotations", 1.0f, "content", 1.0f);
        MultiFieldQueryParser parser = new MultiFieldQueryParser(fields, analyzer, boosts);
        parser.setAllowLeadingWildcard(false);
        Query parsed;
        try {
            parsed = parser.parse(text);
        } catch (org.apache.lucene.queryparser.classic.ParseException e) {
            try {
                parsed = parser.parse(MultiFieldQueryParser.escape(text));
            } catch (org.apache.lucene.queryparser.classic.ParseException impossible) {
                throw new IllegalArgumentException("Could not parse search query", impossible);
            }
        }
        BooleanQuery.Builder ranked = new BooleanQuery.Builder();
        ranked.add(parsed, BooleanClause.Occur.MUST);
        ranked.add(new TermQuery(new Term("classNameExact", text)), BooleanClause.Occur.SHOULD);
        ranked.add(new TermQuery(new Term("methodNameExact", text)), BooleanClause.Occur.SHOULD);
        return ranked.build();
    }

    private String runSearch(Query query, int limit, int offset, boolean prioritizeApplication,
                             String scope, boolean includeBodies) throws IOException {
        IndexSearcher searcher = searchers.acquire();
        try {
            TopDocs top;
            long totalHits;
            if (prioritizeApplication) {
                Query appQuery = filtered(query, "true");
                Query dependencyQuery = filtered(query, "false");
                TopDocs app = searcher.search(appQuery, MAX_SEARCH_HITS);
                TopDocs dependencies = searcher.search(dependencyQuery, MAX_SEARCH_HITS);
                List<org.apache.lucene.search.ScoreDoc> ordered = new ArrayList<>(app.scoreDocs.length + dependencies.scoreDocs.length);
                ordered.addAll(List.of(app.scoreDocs));
                ordered.addAll(List.of(dependencies.scoreDocs));
                int end = Math.min(ordered.size(), offset + limit);
                List<org.apache.lucene.search.ScoreDoc> page = offset >= end
                        ? List.of() : ordered.subList(offset, end);
                long total = app.totalHits.value() + dependencies.totalHits.value();
                var relation = app.totalHits.relation() == org.apache.lucene.search.TotalHits.Relation.EQUAL_TO
                        && dependencies.totalHits.relation() == org.apache.lucene.search.TotalHits.Relation.EQUAL_TO
                        ? org.apache.lucene.search.TotalHits.Relation.EQUAL_TO
                        : org.apache.lucene.search.TotalHits.Relation.GREATER_THAN_OR_EQUAL_TO;
                top = new TopDocs(new org.apache.lucene.search.TotalHits(total, relation),
                        page.toArray(org.apache.lucene.search.ScoreDoc[]::new));
                totalHits = top.totalHits.value();
            } else {
                top = searcher.search(query, Math.min(MAX_SEARCH_HITS, offset + limit));
                totalHits = top.totalHits.value();
            }
            List<Map<String, Object>> matches = new ArrayList<>();
            int from = prioritizeApplication ? 0 : offset;
            for (int i = from; i < top.scoreDocs.length && matches.size() < limit; i++) {
                Document doc = searcher.storedFields().document(top.scoreDocs[i].doc);
                Map<String, Object> result = new LinkedHashMap<>();
                result.put("score", Math.round(top.scoreDocs[i].score * 1000.0) / 1000.0);
                result.put("kind", doc.get("docType"));
                result.put("className", doc.get("className"));
                result.put("methodName", doc.get("methodName"));
                result.put("signature", doc.get("signature"));
                result.put("descriptor", doc.get("descriptor"));
                result.put("artifact", doc.get("artifact"));
                result.put("entry", doc.get("entry"));
                result.put("application", Boolean.parseBoolean(doc.get("application")));
                result.put("classVersion", doc.get("majorVersion"));
                result.put("path", doc.get("path"));
                result.put("bodyIndexed", "true".equals(doc.get("bodyIndexed")));
                String content = doc.get("content");
                if (content == null || content.isBlank()) content = doc.get("signature");
                if (content != null && !content.isBlank()) {
                    result.put("preview", content.length() > 900 ? content.substring(0, 900) + "…" : content);
                }
                matches.add(result);
            }
            Map<String, Object> response = new LinkedHashMap<>();
            response.put("query", query.toString());
            response.put("totalHits", totalHits);
            response.put("totalHitsRelation", top.totalHits.relation().name());
            response.put("offset", offset);
            response.put("limit", limit);
            response.put("bodyIndexState", bodyIndexState);
            response.put("graphIndexState", graphIndexState);
            if (scope != null) appendBodySearchStatus(response, scope, includeBodies);
            response.put("results", matches);
            return json(response);
        } finally {
            searchers.release(searcher);
        }
    }

    private void appendBodySearchStatus(Map<String, Object> response, String scope, boolean includeBodies)
            throws IOException {
        response.put("bodySearchRequested", includeBodies);
        response.put("searchContent", includeBodies ? "symbols_and_method_bodies" : "symbols");
        response.put("symbolIndexState", state);
        response.put("symbolSearchComplete", !refreshRunning.get()
                && (state.equals("ready") || state.equals("completed_with_errors")));
        long scopedDecompilationFailures = includeBodies ? countBodyDecompilationFailures(scope) : 0;
        response.put("bodySearchComplete", includeBodies
                ? countBodyIndexedClasses(scope) >= countClassesInScope(scope) && scopedDecompilationFailures == 0
                : null);
        if (includeBodies) response.put("bodyDecompilationFailures", scopedDecompilationFailures);
        response.put("bodyPrewarmState", bodyPrewarmState);
        response.put("bodyPrewarmPhase", bodyPrewarmPhase);
        response.put("bodyPrewarmTargetScope", bodyPrewarmTargetScope);
        response.put("bodyPrewarmProcessed", bodyPrewarmProcessed);
        response.put("bodyPrewarmTotal", bodyPrewarmTotal);
        response.put("bodyPrewarmIssue", bodyPrewarmIssue);
    }

    private static Query filtered(Query query, String appValue) {
        return new BooleanQuery.Builder()
                .add(query, BooleanClause.Occur.MUST)
                .add(new TermQuery(new Term("application", appValue)), BooleanClause.Occur.MUST)
                .build();
    }

    private Map<String, ExistingClass> readExistingClasses() throws IOException {
        Map<String, ExistingClass> classes = new HashMap<>();
        IndexSearcher searcher = searchers.acquire();
        try {
            int count = searcher.getIndexReader().numDocs();
            TopDocs docs = searcher.search(new TermQuery(new Term("docType", "class")), Math.max(1, count));
            for (var hit : docs.scoreDocs) {
                Document doc = searcher.storedFields().document(hit.doc);
                classes.put(doc.get("classId"), new ExistingClass(doc.get("hash"),
                        Boolean.parseBoolean(doc.get("application"))));
            }
        } finally {
            searchers.release(searcher);
        }
        return classes;
    }

    private record ExistingClass(String hash, boolean application) {
    }

    private Map<String, String> readResourceHashes() throws IOException {
        Map<String, String> hashes = new HashMap<>();
        BooleanQuery query = new BooleanQuery.Builder()
                .add(new TermQuery(new Term("docType", "config")), BooleanClause.Occur.SHOULD)
                .add(new TermQuery(new Term("docType", "template")), BooleanClause.Occur.SHOULD)
                .setMinimumNumberShouldMatch(1)
                .build();
        IndexSearcher searcher = searchers.acquire();
        try {
            int count = searcher.count(query);
            TopDocs docs = searcher.search(query, Math.max(1, count));
            for (var hit : docs.scoreDocs) {
                Document doc = searcher.storedFields().document(hit.doc);
                hashes.put(doc.get("resourceId"), doc.get("hash"));
            }
        } finally {
            searchers.release(searcher);
        }
        return hashes;
    }

    private long countDocuments(String type) throws IOException {
        IndexSearcher searcher = searchers.acquire();
        try {
            return searcher.count(new TermQuery(new Term("docType", type)));
        } finally {
            searchers.release(searcher);
        }
    }

    private long countBodyIndexedClasses() throws IOException {
        return countBodyIndexedClasses("all");
    }

    private long countBodyIndexedClasses(String scope) throws IOException {
        IndexSearcher searcher = searchers.acquire();
        try {
            Query query = new BooleanQuery.Builder()
                    .add(classQueryInScope(scope), BooleanClause.Occur.MUST)
                    .add(new TermQuery(new Term("bodyIndexed", "true")), BooleanClause.Occur.MUST)
                    .build();
            return searcher.count(query);
        } finally {
            searchers.release(searcher);
        }
    }

    private long countBodyDecompilationFailures(String scope) throws IOException {
        IndexSearcher searcher = searchers.acquire();
        try {
            Query query = new BooleanQuery.Builder()
                    .add(classQueryInScope(scope), BooleanClause.Occur.MUST)
                    .add(new TermQuery(new Term("decompilerFailed", "true")), BooleanClause.Occur.MUST)
                    .build();
            return searcher.count(query);
        } finally {
            searchers.release(searcher);
        }
    }

    private long countClassesInScope(String scope) throws IOException {
        IndexSearcher searcher = searchers.acquire();
        try {
            return searcher.count(classQueryInScope(scope));
        } finally {
            searchers.release(searcher);
        }
    }

    private static Query classQueryInScope(String scope) {
        BooleanQuery.Builder builder = new BooleanQuery.Builder()
                .add(new TermQuery(new Term("docType", "class")), BooleanClause.Occur.MUST);
        if (scope.equals("application")) {
            builder.add(new TermQuery(new Term("application", "true")), BooleanClause.Occur.MUST);
        } else if (scope.equals("dependency")) {
            builder.add(new TermQuery(new Term("application", "false")), BooleanClause.Occur.MUST);
        }
        return builder.build();
    }

    private long countGraphIndexedClasses() throws IOException {
        IndexSearcher searcher = searchers.acquire();
        try {
            Query query = new BooleanQuery.Builder()
                    .add(new TermQuery(new Term("docType", "class")), BooleanClause.Occur.MUST)
                    .add(new TermQuery(new Term("graphIndexed", "true")), BooleanClause.Occur.MUST)
                    .build();
            return searcher.count(query);
        } finally {
            searchers.release(searcher);
        }
    }

    private void updateIndexDiagnostics() throws IOException {
        IndexSearcher searcher = searchers.acquire();
        try {
            Query classQuery = new TermQuery(new Term("docType", "class"));
            int totalClasses = searcher.count(classQuery);
            classesWithBodiesIndexed = searcher.count(new BooleanQuery.Builder()
                    .add(classQuery, BooleanClause.Occur.MUST)
                    .add(new TermQuery(new Term("bodyIndexed", "true")), BooleanClause.Occur.MUST).build());
            bodyIndexState = classesWithBodiesIndexed == 0 ? "symbols_only"
                    : classesWithBodiesIndexed >= totalClasses ? "complete" : "partial";
            classesWithGraphIndexed = searcher.count(new BooleanQuery.Builder()
                    .add(classQuery, BooleanClause.Occur.MUST)
                    .add(new TermQuery(new Term("graphIndexed", "true")), BooleanClause.Occur.MUST).build());
            graphIndexState = classesWithGraphIndexed == 0 ? "symbols_only"
                    : classesWithGraphIndexed >= totalClasses ? "complete" : "partial";
            TopDocs docs = searcher.search(classQuery, Math.max(1, totalClasses));
            Set<String> available = new HashSet<>();
            for (var hit : docs.scoreDocs) {
                Document doc = searcher.storedFields().document(hit.doc);
                if (doc.get("className") != null && !doc.get("className").isBlank()) {
                    available.add(doc.get("className"));
                }
            }
            Set<String> missing = new java.util.TreeSet<>();
            for (var hit : docs.scoreDocs) {
                Document doc = searcher.storedFields().document(hit.doc);
                if (!"true".equals(doc.get("application"))) continue;
                for (String reference : doc.getValues("referenceType")) {
                    if (!isPlatformType(reference) && !available.contains(reference)) missing.add(reference);
                }
            }
            missingDependencyTypes = missing.size();
            missingDependencyExamples = missing.stream().limit(100).toList();
            Query unsupportedQuery = new BooleanQuery.Builder()
                    .add(classQuery, BooleanClause.Occur.MUST)
                    .add(new TermQuery(new Term("unsupportedVersion", "true")), BooleanClause.Occur.MUST)
                    .build();
            unsupportedClassFiles = searcher.count(unsupportedQuery);
            classParseErrors = searcher.count(new BooleanQuery.Builder()
                    .add(classQuery, BooleanClause.Occur.MUST)
                    .add(new FieldExistsQuery("error"), BooleanClause.Occur.MUST).build());
            decompilerFailures = searcher.count(new BooleanQuery.Builder()
                    .add(classQuery, BooleanClause.Occur.MUST)
                    .add(new TermQuery(new Term("decompilerFailed", "true")), BooleanClause.Occur.MUST).build());
        } finally {
            searchers.release(searcher);
        }
    }

    private static boolean isPlatformType(String name) {
        return name.startsWith("java.") || name.startsWith("jdk.") || name.startsWith("sun.")
                || name.startsWith("com.sun.") || name.startsWith("javax.xml.")
                || name.startsWith("javax.crypto.") || name.startsWith("javax.management.")
                || name.startsWith("javax.naming.") || name.startsWith("javax.net.")
                || name.startsWith("javax.security.") || name.startsWith("javax.sql.")
                || name.startsWith("javax.swing.") || name.startsWith("javax.tools.")
                || name.startsWith("javax.imageio.") || name.startsWith("javax.sound.")
                || name.startsWith("javax.accessibility.") || name.startsWith("javax.print.")
                || name.startsWith("javax.transaction.xa.") || name.startsWith("javax.annotation.processing.");
    }

    private void loadPersistedStatus() {
        Path statusFile = indexHome.resolve("status.properties");
        if (!Files.isRegularFile(statusFile)) {
            return;
        }
        Properties properties = new Properties();
        try (var input = Files.newInputStream(statusFile)) {
            properties.load(input);
            lastCompletedAt = properties.getProperty("lastCompletedAt", "");
            classesFound = Long.parseLong(properties.getProperty("classesFound", "0"));
            classesIndexed = Long.parseLong(properties.getProperty("classesIndexed", "0"));
            methodsIndexed = Long.parseLong(properties.getProperty("methodsIndexed", "0"));
            classesWithBodiesIndexed = Long.parseLong(properties.getProperty("classesWithBodiesIndexed", "0"));
            bodyIndexState = properties.getProperty("bodyIndexState", "unknown");
            bodyPrewarmState = properties.getProperty("bodyPrewarmState", "not_started");
            bodyPrewarmPhase = properties.getProperty("bodyPrewarmPhase", "idle");
            bodyPrewarmTargetScope = properties.getProperty("bodyPrewarmTargetScope", "all");
            bodyPrewarmProcessed = Long.parseLong(properties.getProperty("bodyPrewarmProcessed", "0"));
            bodyPrewarmTotal = Long.parseLong(properties.getProperty("bodyPrewarmTotal", "0"));
            bodyPrewarmStartedAt = properties.getProperty("bodyPrewarmStartedAt", "");
            bodyPrewarmCompletedAt = properties.getProperty("bodyPrewarmCompletedAt", "");
            bodyPrewarmIssue = properties.getProperty("bodyPrewarmIssue", "");
            bodyPrewarmRunning.set(bodyPrewarmState.equals("scheduled") || bodyPrewarmState.equals("running"));
            classesWithGraphIndexed = Long.parseLong(properties.getProperty("classesWithGraphIndexed", "0"));
            graphIndexState = properties.getProperty("graphIndexState", "unknown");
            resourcesIndexed = Long.parseLong(properties.getProperty("resourcesIndexed", "0"));
            errors = Long.parseLong(properties.getProperty("errors", "0"));
            missingDependencyTypes = Long.parseLong(properties.getProperty("missingDependencyTypes", "0"));
            unsupportedClassFiles = Long.parseLong(properties.getProperty("unsupportedClassFiles", "0"));
            classParseErrors = Long.parseLong(properties.getProperty("classParseErrors", "0"));
            decompilerFailures = Long.parseLong(properties.getProperty("decompilerFailures", "0"));
            classCacheHits = Long.parseLong(properties.getProperty("classCacheHits", "0"));
            classCacheMisses = Long.parseLong(properties.getProperty("classCacheMisses", "0"));
            classCacheEnabled = Boolean.parseBoolean(properties.getProperty("classCacheEnabled",
                    Boolean.toString(classCacheEnabled)));
            classCacheDirectory = properties.getProperty("classCacheDirectory", classCacheDirectory);
            String examples = properties.getProperty("missingDependencyExamples", "");
            missingDependencyExamples = examples.isBlank() ? List.of() : List.of(examples.split(","));
            refreshDurationMs = Long.parseLong(properties.getProperty("refreshDurationMs", "0"));
            String persistedState = properties.getProperty("state", "ready");
            state = persistedState.equals("indexing") ? "failed" : persistedState;
            String issues = properties.getProperty("recentIssues", "");
            recentIssues = issues.isBlank() ? List.of() : List.of(issues.split("\n"));
        } catch (Exception ignored) {
            state = "starting";
        }
    }

    private synchronized void persistStatus() {
        Properties properties = new Properties();
        properties.setProperty("lastCompletedAt", lastCompletedAt);
        properties.setProperty("state", state);
        properties.setProperty("classesFound", Long.toString(classesFound));
        properties.setProperty("classesIndexed", Long.toString(classesIndexed));
        properties.setProperty("methodsIndexed", Long.toString(methodsIndexed));
        properties.setProperty("classesWithBodiesIndexed", Long.toString(classesWithBodiesIndexed));
        properties.setProperty("bodyIndexState", bodyIndexState);
        properties.setProperty("bodyPrewarmState", bodyPrewarmState);
        properties.setProperty("bodyPrewarmPhase", bodyPrewarmPhase);
        properties.setProperty("bodyPrewarmTargetScope", bodyPrewarmTargetScope);
        properties.setProperty("bodyPrewarmProcessed", Long.toString(bodyPrewarmProcessed));
        properties.setProperty("bodyPrewarmTotal", Long.toString(bodyPrewarmTotal));
        properties.setProperty("bodyPrewarmStartedAt", bodyPrewarmStartedAt);
        properties.setProperty("bodyPrewarmCompletedAt", bodyPrewarmCompletedAt);
        properties.setProperty("bodyPrewarmIssue", bodyPrewarmIssue);
        properties.setProperty("classesWithGraphIndexed", Long.toString(classesWithGraphIndexed));
        properties.setProperty("graphIndexState", graphIndexState);
        properties.setProperty("resourcesIndexed", Long.toString(resourcesIndexed));
        properties.setProperty("errors", Long.toString(errors));
        properties.setProperty("recentIssues", String.join("\n", recentIssues));
        properties.setProperty("missingDependencyTypes", Long.toString(missingDependencyTypes));
        properties.setProperty("unsupportedClassFiles", Long.toString(unsupportedClassFiles));
        properties.setProperty("classParseErrors", Long.toString(classParseErrors));
        properties.setProperty("decompilerFailures", Long.toString(decompilerFailures));
        properties.setProperty("classCacheHits", Long.toString(classCacheHits));
        properties.setProperty("classCacheMisses", Long.toString(classCacheMisses));
        properties.setProperty("classCacheEnabled", Boolean.toString(classCacheEnabled));
        properties.setProperty("classCacheDirectory", classCacheDirectory);
        properties.setProperty("missingDependencyExamples", String.join(",", missingDependencyExamples));
        properties.setProperty("refreshDurationMs", Long.toString(refreshDurationMs));
        Path statusFile = indexHome.resolve("status.properties");
        Path temporaryFile = statusFile.resolveSibling(statusFile.getFileName() + ".tmp");
        try (var output = Files.newOutputStream(temporaryFile, StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE)) {
            properties.store(output, "JavaCodeDB index status");
            try {
                Files.move(temporaryFile, statusFile, java.nio.file.StandardCopyOption.ATOMIC_MOVE,
                        java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            } catch (java.nio.file.AtomicMoveNotSupportedException e) {
                Files.move(temporaryFile, statusFile, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (IOException ignored) {
            // The Lucene commit is authoritative; status metadata can be reconstructed by refresh.
        }
    }

    private static int configuredIndexWorkerCount() {
        String configured = System.getProperty("javacodedb.index.workers");
        if (configured == null || configured.isBlank()) {
            configured = System.getenv("JAVACODEDB_INDEX_WORKERS");
        }
        if (configured == null || configured.isBlank()) {
            return Math.max(1, Math.min(DEFAULT_INDEX_WORKERS, Runtime.getRuntime().availableProcessors()));
        }
        int count;
        try {
            count = Integer.parseInt(configured.trim());
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Index worker count must be an integer", e);
        }
        if (count < 1 || count > MAX_INDEX_WORKERS) {
            throw new IllegalArgumentException("Index worker count must be between 1 and " + MAX_INDEX_WORKERS);
        }
        return count;
    }

    private static int configuredLuceneRamBufferMb() {
        String configured = System.getProperty("javacodedb.lucene.ramBufferMb");
        if (configured == null || configured.isBlank()) {
            configured = System.getenv("JAVACODEDB_LUCENE_RAM_BUFFER_MB");
        }
        if (configured == null || configured.isBlank()) {
            return MIN_LUCENE_RAM_BUFFER_MB;
        }
        int bufferMb;
        try {
            bufferMb = Integer.parseInt(configured.trim());
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Lucene RAM buffer size must be an integer", e);
        }
        if (bufferMb < MIN_LUCENE_RAM_BUFFER_MB || bufferMb > MAX_LUCENE_RAM_BUFFER_MB) {
            throw new IllegalArgumentException("Lucene RAM buffer size must be between "
                    + MIN_LUCENE_RAM_BUFFER_MB + " and " + MAX_LUCENE_RAM_BUFFER_MB + " MB");
        }
        return bufferMb;
    }

    private static ThreadPoolExecutor newClassTaskExecutor(int workerCount) {
        AtomicLong threadNumber = new AtomicLong();
        return new ThreadPoolExecutor(workerCount, workerCount, 0, TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(workerCount * 2), task -> {
                    Thread thread = new Thread(task, "javacodedb-class-indexer-" + threadNumber.incrementAndGet());
                    thread.setDaemon(true);
                    return thread;
                }, (task, executor) -> {
                    if (executor.isShutdown()) {
                        throw new RejectedExecutionException("Class indexing executor is shut down");
                    }
                    task.run();
                });
    }

    private static String sha256(byte[] bytes) throws Exception {
        return java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(bytes));
    }

    private static String concise(Exception e) {
        String message = e.getMessage();
        return e.getClass().getSimpleName() + (message == null ? "" : ": " + message);
    }

    private static String json(Object value) {
        if (value == null) return "null";
        if (value instanceof String text) {
            StringBuilder escaped = new StringBuilder("\"");
            for (int i = 0; i < text.length(); i++) {
                char character = text.charAt(i);
                switch (character) {
                    case '"' -> escaped.append("\\\"");
                    case '\\' -> escaped.append("\\\\");
                    case '\b' -> escaped.append("\\b");
                    case '\f' -> escaped.append("\\f");
                    case '\n' -> escaped.append("\\n");
                    case '\r' -> escaped.append("\\r");
                    case '\t' -> escaped.append("\\t");
                    default -> {
                        if (character < 0x20) escaped.append(String.format("\\u%04x", (int) character));
                        else escaped.append(character);
                    }
                }
            }
            return escaped.append('"').toString();
        }
        if (value instanceof Number || value instanceof Boolean) return value.toString();
        if (value instanceof Map<?, ?> map) {
            List<String> parts = new ArrayList<>();
            map.forEach((key, item) -> parts.add(json(String.valueOf(key)) + ":" + json(item)));
            return "{" + String.join(",", parts) + "}";
        }
        if (value instanceof Iterable<?> iterable) {
            List<String> parts = new ArrayList<>();
            iterable.forEach(item -> parts.add(json(item)));
            return "[" + String.join(",", parts) + "]";
        }
        return json(value.toString());
    }

    @Override
    public void close() {
        refreshExecutor.shutdownNow();
        boolean interrupted = false;
        while (!refreshExecutor.isTerminated()) {
            try {
                refreshExecutor.awaitTermination(1, TimeUnit.MINUTES);
            } catch (InterruptedException e) {
                interrupted = true;
            }
        }
        if (!readOnly && bodyPrewarmRunning.get()) {
            bodyPrewarmRunning.set(false);
            bodyPrewarmState = "interrupted";
            bodyPrewarmPhase = "interrupted";
            bodyPrewarmIssue = "Background body prewarm stopped with the MCP session";
            bodyPrewarmCompletedAt = Instant.now().toString();
            persistStatus();
        }
        decompileWorkers.close();
        try {
            searchers.close();
            if (writer != null) writer.close();
            directory.close();
            analyzer.close();
        } catch (IOException ignored) {
        }
        if (interrupted) Thread.currentThread().interrupt();
    }
}
