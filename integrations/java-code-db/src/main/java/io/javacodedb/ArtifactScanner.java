package io.javacodedb;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.zip.ZipFile;
import java.util.Locale;
import java.util.Set;
import java.util.function.Consumer;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/** Streams class files from loose directories and nested Java deployment archives. */
final class ArtifactScanner {
    static final int MAX_NESTED_ARCHIVE_DEPTH = 4;
    private static final int MAX_CLASS_BYTES = 32 * 1024 * 1024;
    private static final int MAX_RESOURCE_BYTES = 4 * 1024 * 1024;
    private static final int MAX_NESTED_ARCHIVE_BYTES = 128 * 1024 * 1024;
    private static final long MAX_ARCHIVE_EXPANDED_BYTES = 1024L * 1024 * 1024;
    private static final int MAX_ARCHIVE_ENTRIES = 500_000;
    private static final Set<String> ARCHIVE_EXTENSIONS = Set.of(".jar", ".war", ".ear", ".zip");

    private final Path workspace;
    private final Consumer<ClassEntry> classConsumer;
    private final Consumer<ResourceEntry> resourceConsumer;
    private final Consumer<String> issueConsumer;
    private long classCount;
    private long artifactCount;
    private Set<String> applicationPackagePrefixes = Set.of();

    ArtifactScanner(Path workspace, Consumer<ClassEntry> classConsumer, Consumer<ResourceEntry> resourceConsumer,
                    Consumer<String> issueConsumer) {
        this.workspace = workspace;
        this.classConsumer = classConsumer;
        this.resourceConsumer = resourceConsumer;
        this.issueConsumer = issueConsumer;
    }

    ScanSummary scan() throws IOException {
        applicationPackagePrefixes = discoverApplicationPackagePrefixes();
        try (Stream<Path> paths = Files.walk(workspace)) {
            var files = paths.filter(Files::isRegularFile).iterator();
            while (files.hasNext()) {
                Path path = files.next();
                if (isInsideIndex(path)) {
                    continue;
                }
                String name = path.getFileName().toString().toLowerCase(Locale.ROOT);
                if (name.endsWith(".class")) {
                    processLooseClass(path);
                } else if (isArchive(name)) {
                    artifactCount++;
                    try (InputStream input = Files.newInputStream(path)) {
                        scanArchive(input, workspace.relativize(path).toString().replace('\\', '/'), "", 0,
                                new ArchiveBudget());
                    } catch (Exception e) {
                        issueConsumer.accept("Could not read " + workspace.relativize(path) + ": " + concise(e));
                    }
                } else if (ResourceIndexer.resourceKind(relative(path)) != null) {
                    processLooseResource(path);
                }
            }
        }
        return new ScanSummary(classCount, artifactCount);
    }

    private void processLooseClass(Path path) {
        try (InputStream input = Files.newInputStream(path)) {
            byte[] bytes = readBounded(input, MAX_CLASS_BYTES);
            String relative = workspace.relativize(path).toString().replace('\\', '/');
            classConsumer.accept(new ClassEntry(relative, relative,
                    isApplicationClassPath(relative, relative), bytes));
            classCount++;
        } catch (Exception e) {
            issueConsumer.accept("Could not read " + workspace.relativize(path) + ": " + concise(e));
        }
    }

    private void processLooseResource(Path path) {
        try (InputStream input = Files.newInputStream(path)) {
            String relative = relative(path);
            resourceConsumer.accept(new ResourceEntry(relative, relative,
                    ResourceIndexer.resourceKind(relative), readBounded(input, MAX_RESOURCE_BYTES)));
        } catch (Exception e) {
            issueConsumer.accept("Could not read " + workspace.relativize(path) + ": " + concise(e));
        }
    }

    private String relative(Path path) {
        return workspace.relativize(path).toString().replace('\\', '/');
    }

    static byte[] readClassEntry(Path workspace, String artifact, String entry) throws IOException {
        Path root = workspace.toAbsolutePath().normalize();
        Path artifactPath = root.resolve(artifact).normalize();
        if (!artifactPath.startsWith(root) || !Files.isRegularFile(artifactPath)) {
            throw new IOException("Indexed artifact is missing or outside the workspace: " + artifact);
        }
        if (artifactPath.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(".class")) {
            if (!artifact.equals(entry)) throw new IOException("Loose class entry does not match its artifact");
            try (InputStream input = Files.newInputStream(artifactPath)) {
                return readBounded(input, MAX_CLASS_BYTES);
            }
        }
        String[] nestedEntries = entry.split("!", -1);
        if (nestedEntries.length == 0 || nestedEntries.length > MAX_NESTED_ARCHIVE_DEPTH + 1) {
            throw new IOException("Indexed class archive nesting exceeds the supported depth");
        }
        for (String nestedEntry : nestedEntries) {
            if (!safeArchiveEntry(nestedEntry)) throw new IOException("Unsafe indexed archive entry path");
        }

        byte[] archiveBytes = null;
        int firstNested = 0;
        try (ZipFile archive = new ZipFile(artifactPath.toFile())) {
            ZipEntry first = archive.getEntry(nestedEntries[0]);
            if (first == null || first.isDirectory()) {
                throw new IOException("Indexed class entry was not found in " + artifact);
            }
            if (nestedEntries.length == 1) {
                try (InputStream input = archive.getInputStream(first)) {
                    return readBounded(input, MAX_CLASS_BYTES);
                }
            }
            try (InputStream input = archive.getInputStream(first)) {
                archiveBytes = readBounded(input, MAX_NESTED_ARCHIVE_BYTES);
            }
            firstNested = 1;
        }

        for (int i = firstNested; i < nestedEntries.length; i++) {
            int maxBytes = i == nestedEntries.length - 1 ? MAX_CLASS_BYTES : MAX_NESTED_ARCHIVE_BYTES;
            archiveBytes = readNestedZipEntry(archiveBytes, nestedEntries[i], maxBytes);
        }
        return archiveBytes;
    }

    private static byte[] readNestedZipEntry(byte[] archiveBytes, String name, int maxBytes) throws IOException {
        long expanded = 0;
        int entries = 0;
        try (ZipInputStream zip = new ZipInputStream(new java.io.ByteArrayInputStream(archiveBytes))) {
            ZipEntry entry;
            while ((entry = zip.getNextEntry()) != null) {
                if (++entries > MAX_ARCHIVE_ENTRIES) throw new IOException("Nested archive entry limit exceeded");
                if (entry.getName().replace('\\', '/').equals(name)) {
                    if (entry.isDirectory()) throw new IOException("Indexed class entry is a directory");
                    return readBounded(zip, maxBytes);
                }
                expanded += drainBounded(zip, MAX_ARCHIVE_EXPANDED_BYTES - expanded);
                if (expanded > MAX_ARCHIVE_EXPANDED_BYTES) {
                    throw new IOException("Nested archive expansion limit exceeded");
                }
                zip.closeEntry();
            }
        }
        throw new IOException("Indexed class entry was not found in nested archive: " + name);
    }

    private static long drainBounded(InputStream input, long remaining) throws IOException {
        byte[] buffer = new byte[8192];
        long total = 0;
        int read;
        while ((read = input.read(buffer)) != -1) {
            total += read;
            if (total > remaining) throw new IOException("Nested archive expansion limit exceeded");
        }
        return total;
    }

    private static boolean safeArchiveEntry(String name) {
        return !name.isBlank() && !name.startsWith("/") && !name.contains("../") && !name.equals("..");
    }

    private void scanArchive(InputStream input, String artifact, String prefix, int depth, ArchiveBudget budget)
            throws IOException {
        if (depth > MAX_NESTED_ARCHIVE_DEPTH) {
            issueConsumer.accept("Nested archive depth limit exceeded at " + artifact + "!" + prefix);
            return;
        }
        try (ZipInputStream zip = new ZipInputStream(input)) {
            ZipEntry entry;
            int entries = 0;
            while ((entry = zip.getNextEntry()) != null) {
                if (++entries > MAX_ARCHIVE_ENTRIES) {
                    issueConsumer.accept("Archive entry limit exceeded at " + artifact + "!" + prefix);
                    return;
                }
                if (entry.isDirectory()) {
                    drainBounded(zip, budget);
                    continue;
                }
                String name = entry.getName().replace('\\', '/');
                if (name.startsWith("/") || name.contains("../") || name.equals("..")) {
                    issueConsumer.accept("Skipped unsafe archive path " + artifact + "!" + prefix + name);
                    drainBounded(zip, budget);
                    continue;
                }
                String nestedPath = prefix.isEmpty() ? name : prefix + "!" + name;
                String lower = name.toLowerCase(Locale.ROOT);
                if (lower.endsWith(".class")) {
                    byte[] bytes = readBounded(zip, MAX_CLASS_BYTES, budget);
                    classConsumer.accept(new ClassEntry(artifact, nestedPath,
                            isApplicationClassPath(artifact + "/" + nestedPath, nestedPath), bytes));
                    classCount++;
                } else if (isArchive(lower)) {
                    byte[] nested = readBounded(zip, MAX_NESTED_ARCHIVE_BYTES, budget);
                    scanArchive(new java.io.ByteArrayInputStream(nested), artifact, nestedPath, depth + 1, budget);
                } else if (ResourceIndexer.resourceKind(nestedPath) != null) {
                    byte[] bytes = readBounded(zip, MAX_RESOURCE_BYTES, budget);
                    resourceConsumer.accept(new ResourceEntry(artifact, nestedPath,
                            ResourceIndexer.resourceKind(nestedPath), bytes));
                } else {
                    drainBounded(zip, budget);
                }
                zip.closeEntry();
            }
        } catch (ArchiveLimitException e) {
            issueConsumer.accept("Archive expansion limit exceeded at " + artifact + "!" + prefix);
        }
    }

    private boolean isInsideIndex(Path path) {
        return path.toAbsolutePath().normalize().startsWith(workspace.resolve(".javacodedb"));
    }

    private static boolean isArchive(String name) {
        return ARCHIVE_EXTENSIONS.stream().anyMatch(name::endsWith);
    }

    private Set<String> discoverApplicationPackagePrefixes() throws IOException {
        Set<String> prefixes = new HashSet<>();
        try (Stream<Path> paths = Files.walk(workspace)) {
            var files = paths.filter(Files::isRegularFile).iterator();
            while (files.hasNext()) {
                Path path = files.next();
                if (isInsideIndex(path)) continue;
                String name = path.getFileName().toString().toLowerCase(Locale.ROOT);
                if (!isArchive(name)) continue;
                try (ZipFile archive = new ZipFile(path.toFile())) {
                    var entries = archive.entries();
                    while (entries.hasMoreElements()) {
                        ZipEntry entry = entries.nextElement();
                        if (entry.isDirectory()) continue;
                        String packageName = packageNameUnderBootClasses(entry.getName());
                        String prefix = reverseDomainPrefix(packageName);
                        if (prefix != null) prefixes.add(prefix);
                    }
                } catch (IOException ignored) {
                    // The main scan reports invalid or unreadable archives with their workspace path.
                }
            }
        }
        return Set.copyOf(prefixes);
    }

    private static String packageNameUnderBootClasses(String entryName) {
        String root = "BOOT-INF/classes/";
        if (entryName.length() < root.length() + 6
                || !entryName.regionMatches(true, 0, root, 0, root.length())
                || !entryName.regionMatches(true, entryName.length() - 6, ".class", 0, 6)) {
            return "";
        }
        return packageNameFromClassEntry(entryName.substring(root.length()));
    }

    /** Infer the conventional reverse-DNS namespace, for example com.simia from com/simia/service/Foo.class. */
    private static String reverseDomainPrefix(String packageName) {
        String[] segments = packageName.split("\\.", 3);
        return segments.length >= 2 ? segments[0] + "." + segments[1] : null;
    }

    private boolean isApplicationClassPath(String path, String classEntry) {
        if (!isLibraryPath(path)) return true;

        String packageName = packageNameFromClassEntry(classEntry);
        int firstSeparator = packageName.indexOf('.');
        if (firstSeparator < 0) return false;
        int secondSeparator = packageName.indexOf('.', firstSeparator + 1);
        String prefix = secondSeparator < 0 ? packageName : packageName.substring(0, secondSeparator);
        return applicationPackagePrefixes.contains(prefix);
    }

    private static boolean isLibraryPath(String path) {
        String normalized = "/" + path.toLowerCase(Locale.ROOT) + "/";
        return normalized.contains("/boot-inf/lib/") || normalized.contains("/web-inf/lib/")
                || normalized.contains("/lib/") || normalized.contains("/libs/");
    }

    private static String packageNameFromClassEntry(String classEntry) {
        int nestedArchive = classEntry.lastIndexOf('!');
        String normalized = classEntry.substring(nestedArchive + 1).replace('\\', '/');
        String multiReleasePrefix = "META-INF/versions/";
        if (normalized.startsWith(multiReleasePrefix)) {
            int versionSeparator = normalized.indexOf('/', multiReleasePrefix.length());
            if (versionSeparator < 0) return "";
            normalized = normalized.substring(versionSeparator + 1);
        }
        int packageSeparator = normalized.lastIndexOf('/');
        return packageSeparator <= 0 ? "" : normalized.substring(0, packageSeparator).replace('/', '.');
    }

    private static byte[] readBounded(InputStream input, int maxBytes) throws IOException {
        return readBounded(input, maxBytes, null);
    }

    private static byte[] readBounded(InputStream input, int maxBytes, ArchiveBudget budget) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int read;
        int total = 0;
        while ((read = input.read(buffer)) != -1) {
            total += read;
            if (total > maxBytes) {
                throw new ArchiveLimitException();
            }
            if (budget != null) {
                budget.add(read);
            }
            out.write(buffer, 0, read);
        }
        return out.toByteArray();
    }

    private static void drainBounded(InputStream input, ArchiveBudget budget) throws IOException {
        byte[] buffer = new byte[8192];
        int read;
        while ((read = input.read(buffer)) != -1) {
            budget.add(read);
        }
    }

    private static String concise(Exception e) {
        String message = e.getMessage();
        return e.getClass().getSimpleName() + (message == null ? "" : ": " + message);
    }

    record ClassEntry(String artifact, String entry, boolean application, byte[] bytes) {
        String id() {
            return artifact + "!" + entry;
        }
    }

    record ScanSummary(long classesFound, long artifactsFound) {
    }

    record ResourceEntry(String artifact, String entry, String kind, byte[] bytes) {
        String id() {
            return artifact + "!" + entry;
        }
    }

    private static final class ArchiveBudget {
        private long expanded;

        void add(long amount) throws ArchiveLimitException {
            expanded += amount;
            if (expanded > MAX_ARCHIVE_EXPANDED_BYTES) {
                throw new ArchiveLimitException();
            }
        }
    }

    private static final class ArchiveLimitException extends IOException {
    }
}
