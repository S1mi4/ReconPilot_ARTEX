package io.javacodedb;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.TimeUnit;

/** Keeps decompiler failures and memory pressure outside the MCP process. */
final class DecompileWorker implements AutoCloseable {
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(45);
    private static final int MAX_REQUESTS_PER_PROCESS = 2_000;
    private static final int MAX_CLASS_BYTES = 32 * 1024 * 1024;
    private static final int MAX_RESPONSE_BYTES = 16 * 1024 * 1024;

    private final Path classFile;
    private Process process;
    private DataOutputStream input;
    private ArrayBlockingQueue<Response> responses;
    private int requestCount;

    DecompileWorker(Path temporaryDirectory) {
        this.classFile = temporaryDirectory.resolve("decompile.class");
    }

    synchronized String decompile(byte[] classBytes) {
        try {
            if (classBytes.length > MAX_CLASS_BYTES) {
                return "";
            }
            ensureRunning();
            input.writeInt(classBytes.length);
            input.write(classBytes);
            input.flush();

            long deadline = System.nanoTime() + REQUEST_TIMEOUT.toNanos();
            Response response = null;
            while (response == null && System.nanoTime() < deadline) {
                response = responses.poll(250, TimeUnit.MILLISECONDS);
                if (response == null && !process.isAlive()) break;
            }
            requestCount++;
            if (response == null || response.transportFailure()) {
                restart();
                return "";
            }
            if (requestCount >= MAX_REQUESTS_PER_PROCESS) {
                restart();
            }
            return response.success()
                    ? new String(response.payload(), StandardCharsets.UTF_8)
                    : "";
        } catch (Exception e) {
            restart();
            return "";
        }
    }

    private void ensureRunning() throws IOException {
        if (process != null && process.isAlive()) {
            return;
        }
        closeProcess();
        Files.createDirectories(classFile.getParent());
        String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
        ProcessBuilder builder = new ProcessBuilder(java, "-Xms32m", "-Xmx512m",
                "-XX:MaxMetaspaceSize=192m", "-cp", System.getProperty("java.class.path"),
                Main.class.getName(), "--decompile-worker", classFile.toString());
        builder.redirectError(ProcessBuilder.Redirect.INHERIT);
        process = builder.start();
        input = new DataOutputStream(new BufferedOutputStream(process.getOutputStream()));
        responses = new ArrayBlockingQueue<>(1);
        ArrayBlockingQueue<Response> responseQueue = responses;
        DataInputStream output = new DataInputStream(new BufferedInputStream(process.getInputStream()));
        Thread reader = new Thread(() -> readResponses(output, responseQueue),
                "javacodedb-decompiler-output");
        reader.setDaemon(true);
        reader.start();
        requestCount = 0;
    }

    private static void readResponses(DataInputStream output, ArrayBlockingQueue<Response> responseQueue) {
        try (output) {
            while (true) {
                int frameLength;
                try {
                    frameLength = output.readInt();
                } catch (EOFException e) {
                    responseQueue.offer(Response.transportError());
                    return;
                }
                if (frameLength == Integer.MIN_VALUE) {
                    throw new IOException("Invalid decompiler response frame");
                }
                boolean success = frameLength >= 0;
                int length = Math.abs(frameLength);
                if (length > MAX_RESPONSE_BYTES) {
                    throw new IOException("Decompiler response exceeded size limit");
                }
                byte[] payload = output.readNBytes(length);
                if (payload.length != length) {
                    throw new EOFException("Incomplete decompiler response");
                }
                responseQueue.put(new Response(success, false, payload));
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            responseQueue.offer(Response.transportError());
        } catch (IOException e) {
            responseQueue.offer(Response.transportError());
        }
    }

    private synchronized void restart() {
        closeProcess();
    }

    private void closeProcess() {
        if (input != null) {
            try {
                input.close();
            } catch (IOException ignored) {
            }
        }
        if (process != null) {
            process.destroy();
            try {
                if (!process.waitFor(500, TimeUnit.MILLISECONDS)) {
                    process.destroyForcibly();
                    process.waitFor(500, TimeUnit.MILLISECONDS);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                process.destroyForcibly();
            }
        }
        process = null;
        input = null;
        responses = null;
        requestCount = 0;
    }

    @Override
    public synchronized void close() {
        closeProcess();
        try {
            Files.deleteIfExists(classFile);
        } catch (IOException ignored) {
        }
    }

    private record Response(boolean success, boolean transportFailure, byte[] payload) {
        private static Response transportError() {
            return new Response(false, true, new byte[0]);
        }
    }
}
