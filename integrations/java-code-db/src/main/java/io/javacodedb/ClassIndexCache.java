package io.javacodedb;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Stream;
import java.util.zip.CheckedInputStream;
import java.util.zip.CheckedOutputStream;
import java.util.zip.CRC32;

/** Persistent content-addressed cache for the expensive class analysis result. */
final class ClassIndexCache {
    private static final int MAGIC = 0x4A434443;
    private static final int FORMAT_VERSION = 3;
    private static final int MAX_STRING_BYTES = 64 * 1024 * 1024;
    private static final int MAX_COLLECTION_ITEMS = 2_000_000;
    private static final long MAX_ENTRY_BYTES = 128L * 1024 * 1024;
    private static final long MAX_CACHE_BYTES = 4L * 1024 * 1024 * 1024;
    private static final Set<PosixFilePermission> CACHE_FILE_PERMISSIONS = Set.of(
            PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);

    private final boolean enabled;
    private final Path directory;
    private final AtomicLong hits = new AtomicLong();
    private final AtomicLong misses = new AtomicLong();
    private final AtomicLong writes = new AtomicLong();

    private ClassIndexCache(boolean enabled, Path directory) {
        this.enabled = enabled;
        this.directory = directory.resolve("class-analysis-v" + FORMAT_VERSION);
    }

    static ClassIndexCache configured() {
        String enabledValue = setting("javacodedb.cache.enabled", "JAVACODEDB_CACHE_ENABLED");
        boolean enabled = enabledValue == null || !enabledValue.trim().equalsIgnoreCase("false");
        String configuredDirectory = setting("javacodedb.cache.dir", "JAVACODEDB_CACHE_DIR");
        Path directory = configuredDirectory == null || configuredDirectory.isBlank()
                ? Path.of(System.getProperty("user.home"), ".javacodedb", "cache")
                : Path.of(configuredDirectory).toAbsolutePath().normalize();
        directory = directory.toAbsolutePath().normalize();
        return new ClassIndexCache(enabled, directory);
    }

    BytecodeIndexer.IndexedClass get(String hash, ArtifactScanner.ClassEntry entry) {
        if (!enabled || !validHash(hash)) {
            return null;
        }
        Path cacheFile = cacheFile(hash);
        try {
            long fileSize = Files.size(cacheFile);
            if (fileSize <= 0 || fileSize > MAX_ENTRY_BYTES) {
                throw new IOException("Invalid class cache entry size");
            }
            CRC32 checksum = new CRC32();
            BytecodeIndexer.IndexedClass indexed;
            try (DataInputStream input = new DataInputStream(new CheckedInputStream(
                    new BufferedInputStream(Files.newInputStream(cacheFile)), checksum))) {
                indexed = readIndexedClass(input, entry, hash);
                long actualChecksum = checksum.getValue();
                long expectedChecksum = input.readLong();
                if (actualChecksum != expectedChecksum || input.read() != -1) {
                    throw new IOException("Class cache checksum mismatch");
                }
            }
            hits.incrementAndGet();
            return indexed;
        } catch (Exception e) {
            misses.incrementAndGet();
            try {
                Files.deleteIfExists(cacheFile);
            } catch (IOException ignored) {
            }
            return null;
        }
    }

    void put(BytecodeIndexer.IndexedClass indexed) {
        if (!enabled || !validHash(indexed.hash())) {
            return;
        }
        Path cacheFile = cacheFile(indexed.hash());
        Path temporary = null;
        try {
            Files.createDirectories(cacheFile.getParent());
            temporary = Files.createTempFile(cacheFile.getParent(), "entry-", ".tmp");
            CRC32 checksum = new CRC32();
            try (DataOutputStream output = new DataOutputStream(new CheckedOutputStream(
                    new BufferedOutputStream(Files.newOutputStream(temporary, StandardOpenOption.WRITE)), checksum))) {
                writeIndexedClass(output, indexed);
            }
            try (DataOutputStream output = new DataOutputStream(new BufferedOutputStream(Files.newOutputStream(
                    temporary, StandardOpenOption.APPEND)))) {
                output.writeLong(checksum.getValue());
            }
            long size = Files.size(temporary);
            if (size > MAX_ENTRY_BYTES) {
                return;
            }
            restrictFilePermissions(temporary);
            try {
                Files.move(temporary, cacheFile, StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(temporary, cacheFile, StandardCopyOption.REPLACE_EXISTING);
            }
            writes.incrementAndGet();
        } catch (Exception ignored) {
            // The cache is an optimization; a write failure must not fail indexing.
        } finally {
            if (temporary != null) {
                try {
                    Files.deleteIfExists(temporary);
                } catch (IOException ignored) {
                }
            }
        }
    }

    void resetStats() {
        hits.set(0);
        misses.set(0);
        writes.set(0);
    }

    long hits() {
        return hits.get();
    }

    long misses() {
        return misses.get();
    }

    boolean enabled() {
        return enabled;
    }

    Path directory() {
        return directory;
    }

    void pruneIfNeeded() {
        if (!enabled || writes.get() == 0 || !Files.isDirectory(directory)) {
            return;
        }
        List<CacheFile> cacheFiles = new ArrayList<>();
        long totalBytes = 0;
        try (Stream<Path> paths = Files.walk(directory)) {
            for (Path path : paths.filter(Files::isRegularFile).filter(file -> file.toString().endsWith(".cidx")).toList()) {
                long size = Files.size(path);
                totalBytes += size;
                cacheFiles.add(new CacheFile(path, size, Files.getLastModifiedTime(path).toMillis()));
            }
        } catch (IOException ignored) {
            return;
        }
        if (totalBytes <= MAX_CACHE_BYTES) {
            return;
        }
        cacheFiles.sort(Comparator.comparingLong(CacheFile::modifiedAt));
        for (CacheFile cacheFile : cacheFiles) {
            if (totalBytes <= MAX_CACHE_BYTES) break;
            try {
                if (Files.deleteIfExists(cacheFile.path())) {
                    totalBytes -= cacheFile.size();
                }
            } catch (IOException ignored) {
            }
        }
    }

    private Path cacheFile(String hash) {
        return directory.resolve(hash.substring(0, 2)).resolve(hash + ".cidx");
    }

    private static String setting(String property, String environmentVariable) {
        String value = System.getProperty(property);
        return value == null || value.isBlank() ? System.getenv(environmentVariable) : value;
    }

    private static boolean validHash(String hash) {
        return hash != null && hash.length() == 64
                && hash.chars().allMatch(character -> character >= '0' && character <= '9'
                || character >= 'a' && character <= 'f');
    }

    private static BytecodeIndexer.IndexedClass readIndexedClass(DataInputStream input,
                                                                  ArtifactScanner.ClassEntry entry,
                                                                  String expectedHash) throws IOException {
        if (input.readInt() != MAGIC || input.readInt() != FORMAT_VERSION) {
            throw new IOException("Unsupported class cache format");
        }
        String hash = readString(input);
        if (!expectedHash.equals(hash)) {
            throw new IOException("Class cache key mismatch");
        }
        String className = readString(input);
        String packageName = readString(input);
        int majorVersion = input.readInt();
        int access = input.readInt();
        String superName = readString(input);
        List<String> interfaces = readStrings(input);
        List<String> annotations = readStrings(input);
        List<BytecodeIndexer.MethodMetadata> methods = readMethods(input);
        List<BytecodeIndexer.MethodRecord> methodRecords = readMethodRecords(input);
        List<BytecodeIndexer.Endpoint> endpoints = readEndpoints(input);
        Set<String> referencedTypes = Set.copyOf(readStrings(input));
        String source = readString(input);
        String error = readNullableString(input);
        boolean graphIndexed = input.readBoolean();
        boolean bodyIndexed = input.readBoolean();
        return new BytecodeIndexer.IndexedClass(entry, hash, className, packageName, majorVersion, access,
                superName, interfaces, annotations, methods, methodRecords, endpoints, referencedTypes, source, error,
                graphIndexed, bodyIndexed);
    }

    private static void writeIndexedClass(DataOutputStream output, BytecodeIndexer.IndexedClass indexed)
            throws IOException {
        output.writeInt(MAGIC);
        output.writeInt(FORMAT_VERSION);
        writeString(output, indexed.hash());
        writeString(output, indexed.className());
        writeString(output, indexed.packageName());
        output.writeInt(indexed.majorVersion());
        output.writeInt(indexed.access());
        writeString(output, indexed.superName());
        writeStrings(output, indexed.interfaces());
        writeStrings(output, indexed.annotations());
        writeMethods(output, indexed.methods());
        writeMethodRecords(output, indexed.methodRecords());
        writeEndpoints(output, indexed.endpoints());
        writeStrings(output, indexed.referencedTypes().stream().sorted().toList());
        writeString(output, indexed.source());
        writeNullableString(output, indexed.error());
        output.writeBoolean(indexed.graphIndexed());
        output.writeBoolean(indexed.bodyIndexed());
    }

    private static void writeMethods(DataOutputStream output, List<BytecodeIndexer.MethodMetadata> methods)
            throws IOException {
        writeCount(output, methods.size());
        for (BytecodeIndexer.MethodMetadata method : methods) {
            writeString(output, method.name());
            writeString(output, method.descriptor());
            writeString(output, method.signature());
            writeCalls(output, method.calls());
            writeEndpoints(output, method.endpoints());
        }
    }

    private static List<BytecodeIndexer.MethodMetadata> readMethods(DataInputStream input) throws IOException {
        int count = readCount(input);
        List<BytecodeIndexer.MethodMetadata> methods = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            methods.add(new BytecodeIndexer.MethodMetadata(readString(input), readString(input), readString(input),
                    readCalls(input), readEndpoints(input)));
        }
        return List.copyOf(methods);
    }

    private static void writeMethodRecords(DataOutputStream output, List<BytecodeIndexer.MethodRecord> methods)
            throws IOException {
        writeCount(output, methods.size());
        for (BytecodeIndexer.MethodRecord method : methods) {
            writeString(output, method.name());
            writeString(output, method.descriptor());
            writeString(output, method.signature());
            writeCalls(output, method.calls());
            writeEndpoints(output, method.endpoints());
            writeString(output, method.source());
        }
    }

    private static List<BytecodeIndexer.MethodRecord> readMethodRecords(DataInputStream input) throws IOException {
        int count = readCount(input);
        List<BytecodeIndexer.MethodRecord> methods = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            methods.add(new BytecodeIndexer.MethodRecord(readString(input), readString(input), readString(input),
                    readCalls(input), readEndpoints(input), readString(input)));
        }
        return List.copyOf(methods);
    }

    private static void writeCalls(DataOutputStream output, List<BytecodeIndexer.CallEdge> calls) throws IOException {
        writeCount(output, calls.size());
        for (BytecodeIndexer.CallEdge call : calls) {
            writeString(output, call.target());
            writeString(output, call.kind());
        }
    }

    private static List<BytecodeIndexer.CallEdge> readCalls(DataInputStream input) throws IOException {
        int count = readCount(input);
        List<BytecodeIndexer.CallEdge> calls = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            calls.add(new BytecodeIndexer.CallEdge(readString(input), readString(input)));
        }
        return List.copyOf(calls);
    }

    private static void writeEndpoints(DataOutputStream output, List<BytecodeIndexer.Endpoint> endpoints)
            throws IOException {
        writeCount(output, endpoints.size());
        for (BytecodeIndexer.Endpoint endpoint : endpoints) {
            writeString(output, endpoint.route());
            writeString(output, endpoint.httpMethod());
            writeString(output, endpoint.className());
            writeString(output, endpoint.methodName());
            writeString(output, endpoint.descriptor());
        }
    }

    private static List<BytecodeIndexer.Endpoint> readEndpoints(DataInputStream input) throws IOException {
        int count = readCount(input);
        List<BytecodeIndexer.Endpoint> endpoints = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            endpoints.add(new BytecodeIndexer.Endpoint(readString(input), readString(input), readString(input),
                    readString(input), readString(input)));
        }
        return List.copyOf(endpoints);
    }

    private static void writeStrings(DataOutputStream output, List<String> values) throws IOException {
        writeCount(output, values.size());
        for (String value : values) writeString(output, value);
    }

    private static List<String> readStrings(DataInputStream input) throws IOException {
        int count = readCount(input);
        List<String> values = new ArrayList<>(count);
        for (int i = 0; i < count; i++) values.add(readString(input));
        return List.copyOf(values);
    }

    private static void writeNullableString(DataOutputStream output, String value) throws IOException {
        output.writeBoolean(value != null);
        if (value != null) writeString(output, value);
    }

    private static String readNullableString(DataInputStream input) throws IOException {
        return input.readBoolean() ? readString(input) : null;
    }

    private static void writeString(DataOutputStream output, String value) throws IOException {
        byte[] bytes = value.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        if (bytes.length > MAX_STRING_BYTES) throw new IOException("Class cache string exceeded size limit");
        output.writeInt(bytes.length);
        output.write(bytes);
    }

    private static String readString(DataInputStream input) throws IOException {
        int length = input.readInt();
        if (length < 0 || length > MAX_STRING_BYTES) throw new IOException("Invalid class cache string length");
        byte[] bytes = input.readNBytes(length);
        if (bytes.length != length) throw new EOFException("Incomplete class cache string");
        return new String(bytes, java.nio.charset.StandardCharsets.UTF_8);
    }

    private static void writeCount(DataOutputStream output, int count) throws IOException {
        if (count < 0 || count > MAX_COLLECTION_ITEMS) throw new IOException("Invalid class cache item count");
        output.writeInt(count);
    }

    private static int readCount(DataInputStream input) throws IOException {
        int count = input.readInt();
        if (count < 0 || count > MAX_COLLECTION_ITEMS) throw new IOException("Invalid class cache item count");
        return count;
    }

    private static void restrictFilePermissions(Path path) {
        try {
            Files.setPosixFilePermissions(path, CACHE_FILE_PERMISSIONS);
        } catch (UnsupportedOperationException | IOException ignored) {
        }
    }

    private static record CacheFile(Path path, long size, long modifiedAt) {
    }
}
