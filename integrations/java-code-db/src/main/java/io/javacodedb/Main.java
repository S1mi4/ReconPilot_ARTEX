package io.javacodedb;

import java.nio.file.Path;
import java.util.concurrent.CountDownLatch;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.nio.charset.StandardCharsets;

public final class Main {
    private Main() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length > 0 && "--decompile-worker".equals(args[0])) {
            if (args.length != 2) {
                throw new IllegalArgumentException("Decompiler worker requires a reusable class-file path");
            }
            runDecompilerWorker(Path.of(args[1]));
            return;
        }
        if (args.length > 0 && CliApp.isCommand(args[0])) {
            int exitCode = CliApp.run(args);
            if (exitCode != 0) System.exit(exitCode);
            return;
        }
        Path workspace = parseWorkspace(args);
        if (workspace == null) {
            System.err.println("Usage: java -jar java-code-db.jar --workspace <path>");
            System.exit(2);
            return;
        }
        workspace = workspace.toAbsolutePath().normalize();
        if (!java.nio.file.Files.isDirectory(workspace)) {
            throw new IllegalArgumentException("Workspace is not a directory: " + workspace);
        }

        BodyPrewarmCoordinator.awaitIdle(workspace);
        IndexService indexService = new IndexService(workspace);
        indexService.startBackgroundRefresh(true);
        McpServerApp server = new McpServerApp(indexService);
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            server.close();
            indexService.close();
        }, "javacodedb-shutdown"));
        server.start();
        new CountDownLatch(1).await();
    }

    private static void runDecompilerWorker(Path classFile) throws Exception {
        Files.createDirectories(classFile.toAbsolutePath().getParent());
        try (DataInputStream input = new DataInputStream(new BufferedInputStream(System.in));
             DataOutputStream output = new DataOutputStream(new BufferedOutputStream(System.out))) {
            while (true) {
                int classLength;
                try {
                    classLength = input.readInt();
                } catch (EOFException e) {
                    return;
                }
                if (classLength < 0 || classLength > 32 * 1024 * 1024) {
                    throw new IOException("Invalid class-file frame length: " + classLength);
                }
                byte[] classBytes = input.readNBytes(classLength);
                if (classBytes.length != classLength) {
                    throw new EOFException("Incomplete class-file frame");
                }
                try {
                    Files.write(classFile, classBytes, StandardOpenOption.CREATE,
                            StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);
                    String source = BytecodeIndexer.decompileClassFile(classFile);
                    writeDecompilerResponse(output, source.getBytes(StandardCharsets.UTF_8), true);
                } catch (Throwable e) {
                    String error = e.getClass().getSimpleName() + ": " + String.valueOf(e.getMessage());
                    byte[] payload = error.getBytes(StandardCharsets.UTF_8);
                    if (payload.length > 16 * 1024 * 1024) {
                        payload = java.util.Arrays.copyOf(payload, 16 * 1024 * 1024);
                    }
                    writeDecompilerResponse(output, payload, false);
                }
            }
        } finally {
            Files.deleteIfExists(classFile);
        }
    }

    private static void writeDecompilerResponse(DataOutputStream output, byte[] payload, boolean success)
            throws IOException {
        if (!success && payload.length == 0) {
            payload = new byte[]{'!'};
        }
        output.writeInt(success ? payload.length : -Math.max(1, payload.length));
        output.write(payload);
        output.flush();
    }

    private static Path parseWorkspace(String[] args) {
        for (int i = 0; i < args.length; i++) {
            if ("--workspace".equals(args[i]) && i + 1 < args.length) {
                return Path.of(args[i + 1]);
            }
        }
        return null;
    }
}
