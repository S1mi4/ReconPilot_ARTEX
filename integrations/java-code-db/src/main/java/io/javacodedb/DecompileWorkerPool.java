package io.javacodedb;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;

/** A fixed set of isolated decompiler processes shared by index workers. */
final class DecompileWorkerPool implements AutoCloseable {
    private final List<DecompileWorker> workers;
    private final ArrayBlockingQueue<DecompileWorker> available;

    DecompileWorkerPool(int size, Path temporaryDirectory) {
        if (size < 1) {
            throw new IllegalArgumentException("Decompiler worker count must be positive");
        }
        this.workers = new ArrayList<>(size);
        this.available = new ArrayBlockingQueue<>(size);
        for (int i = 0; i < size; i++) {
            DecompileWorker worker = new DecompileWorker(temporaryDirectory.resolve("decompiler-" + i));
            workers.add(worker);
            available.add(worker);
        }
    }

    String decompile(byte[] classBytes) throws InterruptedException {
        DecompileWorker worker = available.take();
        try {
            return worker.decompile(classBytes);
        } finally {
            available.add(worker);
        }
    }

    @Override
    public void close() {
        workers.forEach(DecompileWorker::close);
    }
}
