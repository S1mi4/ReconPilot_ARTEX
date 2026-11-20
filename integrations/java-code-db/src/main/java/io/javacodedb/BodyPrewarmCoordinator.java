package io.javacodedb;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.TimeUnit;
import java.util.Properties;

/** Coordinates the detached body-indexing process with other writable CLI operations. */
final class BodyPrewarmCoordinator {
    private static final String STATUS_FILE = "status.properties";
    private static final String LOCK_FILE = "body-prewarm.lock";
    private static final Duration SCHEDULE_GRACE = Duration.ofMinutes(2);

    private BodyPrewarmCoordinator() {
    }

    static LockHandle acquire(Path workspace) throws IOException, InterruptedException {
        Path indexHome = workspace.resolve(".javacodedb");
        Files.createDirectories(indexHome);
        FileChannel channel = FileChannel.open(indexHome.resolve(LOCK_FILE),
                StandardOpenOption.CREATE, StandardOpenOption.WRITE);
        try {
            while (true) {
                try {
                    FileLock lock = channel.tryLock();
                    if (lock != null) return new LockHandle(channel, lock);
                } catch (OverlappingFileLockException ignored) {
                    // Another prewarm in this JVM owns the lock; wait for it to finish.
                }
                Thread.sleep(500);
            }
        } catch (IOException | InterruptedException | RuntimeException e) {
            channel.close();
            throw e;
        }
    }

    static void awaitIdle(Path workspace) throws IOException, InterruptedException {
        Path indexHome = workspace.resolve(".javacodedb");
        if (!Files.isDirectory(indexHome)) return;
        Path lockPath = indexHome.resolve(LOCK_FILE);
        while (true) {
            boolean locked = false;
            try (FileChannel channel = FileChannel.open(lockPath,
                    StandardOpenOption.CREATE, StandardOpenOption.WRITE)) {
                try (FileLock lock = channel.tryLock()) {
                    if (lock == null) {
                        locked = true;
                    }
                } catch (OverlappingFileLockException e) {
                    locked = true;
                }
            }
            if (locked) {
                Thread.sleep(500);
                continue;
            }

            Properties status = readStatus(indexHome);
            String state = status.getProperty("bodyPrewarmState", "not_started");
            if (state.equals("running")) {
                markInterrupted(indexHome, status, "Background prewarm stopped before completion");
            } else if (state.equals("scheduled")) {
                Instant scheduledAt = parseInstant(status.getProperty("bodyPrewarmStartedAt", ""));
                if (scheduledAt == null
                        || Duration.between(scheduledAt, Instant.now()).compareTo(SCHEDULE_GRACE) > 0) {
                    markInterrupted(indexHome, status, "Scheduled prewarm process did not start");
                } else {
                    Thread.sleep(500);
                    continue;
                }
            }
            return;
        }
    }

    static boolean awaitScopeReady(Path workspace, String scope) throws IOException, InterruptedException {
        if (IndexService.isBodyScopeComplete(workspace, scope)) return true;
        Path indexHome = workspace.resolve(".javacodedb");
        if (!Files.isDirectory(indexHome)) return false;
        Path lockPath = indexHome.resolve(LOCK_FILE);
        while (true) {
            Properties status = readStatus(indexHome);
            String state = status.getProperty("bodyPrewarmState", "not_started");
            String phase = status.getProperty("bodyPrewarmPhase", "idle");
            boolean locked = isLockHeld(lockPath);

            if (scope.equalsIgnoreCase("application")
                    && (phase.equals("application_complete") || phase.equals("dependency_bodies")
                            || state.equals("complete"))) {
                return IndexService.isBodyScopeComplete(workspace, scope);
            }
            if (!state.equals("scheduled") && !state.equals("running")) {
                boolean complete = IndexService.isBodyScopeComplete(workspace, scope);
                if (complete || !locked) return complete;
            }

            if (!locked && state.equals("scheduled")) {
                Instant scheduledAt = parseInstant(status.getProperty("bodyPrewarmStartedAt", ""));
                if (scheduledAt == null
                        || Duration.between(scheduledAt, Instant.now()).compareTo(SCHEDULE_GRACE) > 0) {
                    awaitIdle(workspace);
                    return IndexService.isBodyScopeComplete(workspace, scope);
                }
            } else if (!locked && state.equals("running")) {
                awaitIdle(workspace);
                return IndexService.isBodyScopeComplete(workspace, scope);
            }
            Thread.sleep(500);
        }
    }

    static void schedule(Path workspace) throws IOException {
        Path indexHome = workspace.resolve(".javacodedb");
        Files.createDirectories(indexHome);
        Path statusPath = indexHome.resolve(STATUS_FILE);
        Properties status = readStatus(indexHome);
        status.setProperty("bodyPrewarmState", "scheduled");
        status.setProperty("bodyPrewarmPhase", "application");
        status.setProperty("bodyPrewarmStartedAt", Instant.now().toString());
        status.setProperty("bodyPrewarmCompletedAt", "");
        status.setProperty("bodyPrewarmProcessed", status.getProperty("classesWithBodiesIndexed", "0"));
        status.setProperty("bodyPrewarmTotal", status.getProperty("classesIndexed", "0"));
        status.setProperty("bodyPrewarmTargetScope", "all");
        status.setProperty("bodyPrewarmIssue", "");
        writeStatus(statusPath, status);

        String javaName = System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT).contains("win")
                ? "java.exe" : "java";
        boolean windows = javaName.endsWith(".exe");
        Path java = Path.of(System.getProperty("java.home"), "bin", javaName);
        Path log = indexHome.resolve("body-prewarm.log");
        try {
            java.util.List<String> command = new java.util.ArrayList<>();
            if (!windows) command.add("nohup");
            command.add(java.toString());
            command.add("-cp");
            command.add(System.getProperty("java.class.path"));
            command.add(Main.class.getName());
            command.add("prewarm");
            command.add("--workspace");
            command.add(workspace.toAbsolutePath().normalize().toString());
            Process process;
            try {
                process = startDetached(command, log);
            } catch (IOException e) {
                if (windows) throw e;
                command.removeFirst();
                process = startDetached(command, log);
            }
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(30);
            while (System.nanoTime() < deadline) {
                String state = readStatus(indexHome).getProperty("bodyPrewarmState", "scheduled");
                if (!state.equals("scheduled") || isLockHeld(indexHome.resolve(LOCK_FILE))) return;
                if (!process.isAlive()) {
                    status = readStatus(indexHome);
                    status.setProperty("bodyPrewarmState", "failed");
                    status.setProperty("bodyPrewarmPhase", "failed");
                    status.setProperty("bodyPrewarmCompletedAt", Instant.now().toString());
                    status.setProperty("bodyPrewarmIssue", "Background prewarm process exited before starting (exit "
                            + process.exitValue() + "); see " + log);
                    writeStatus(statusPath, status);
                    return;
                }
                Thread.sleep(100);
            }
        } catch (IOException e) {
            status.setProperty("bodyPrewarmState", "failed");
            status.setProperty("bodyPrewarmCompletedAt", Instant.now().toString());
            status.setProperty("bodyPrewarmIssue", "Could not start background prewarm: " + e.getMessage());
            writeStatus(statusPath, status);
            throw e;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while waiting for body prewarm to start", e);
        }
    }

    static void markFailure(Path workspace, String issue) {
        Path indexHome = workspace.resolve(".javacodedb");
        try {
            Properties status = readStatus(indexHome);
            status.setProperty("bodyPrewarmState", "failed");
            status.setProperty("bodyPrewarmPhase", "failed");
            status.setProperty("bodyPrewarmCompletedAt", Instant.now().toString());
            status.setProperty("bodyPrewarmIssue", issue == null ? "Body prewarm failed" : issue);
            writeStatus(indexHome.resolve(STATUS_FILE), status);
        } catch (IOException ignored) {
            // Preserve the original failure as the CLI error.
        }
    }

    private static boolean isLockHeld(Path lockPath) throws IOException {
        try (FileChannel channel = FileChannel.open(lockPath,
                StandardOpenOption.CREATE, StandardOpenOption.WRITE)) {
            try (FileLock lock = channel.tryLock()) {
                return lock == null;
            } catch (OverlappingFileLockException e) {
                return true;
            }
        }
    }

    private static Process startDetached(java.util.List<String> command, Path log) throws IOException {
        return new ProcessBuilder(command)
                .redirectOutput(ProcessBuilder.Redirect.appendTo(log.toFile()))
                .redirectErrorStream(true)
                .start();
    }

    private static void markInterrupted(Path indexHome, Properties status, String issue) throws IOException {
        status.setProperty("bodyPrewarmState", "interrupted");
        status.setProperty("bodyPrewarmPhase", "interrupted");
        status.setProperty("bodyPrewarmCompletedAt", Instant.now().toString());
        status.setProperty("bodyPrewarmIssue", issue);
        writeStatus(indexHome.resolve(STATUS_FILE), status);
    }

    private static Properties readStatus(Path indexHome) throws IOException {
        Properties properties = new Properties();
        Path statusPath = indexHome.resolve(STATUS_FILE);
        if (Files.isRegularFile(statusPath)) {
            try (var input = Files.newInputStream(statusPath)) {
                properties.load(input);
            }
        }
        return properties;
    }

    private static void writeStatus(Path statusPath, Properties properties) throws IOException {
        Path temporary = statusPath.resolveSibling(statusPath.getFileName() + ".tmp");
        try (var output = Files.newOutputStream(temporary,
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE)) {
            properties.store(output, "JavaCodeDB index status");
        }
        try {
            Files.move(temporary, statusPath, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (java.nio.file.AtomicMoveNotSupportedException e) {
            Files.move(temporary, statusPath, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private static Instant parseInstant(String value) {
        if (value == null || value.isBlank()) return null;
        try {
            return Instant.parse(value);
        } catch (RuntimeException ignored) {
            return null;
        }
    }

    static final class LockHandle implements AutoCloseable {
        private final FileChannel channel;
        private final FileLock lock;

        private LockHandle(FileChannel channel, FileLock lock) {
            this.channel = channel;
            this.lock = lock;
        }

        @Override
        public void close() throws IOException {
            try {
                lock.release();
            } finally {
                channel.close();
            }
        }
    }
}
