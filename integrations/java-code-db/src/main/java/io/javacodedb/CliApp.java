package io.javacodedb;

import org.apache.lucene.index.DirectoryReader;
import org.apache.lucene.store.Directory;
import org.apache.lucene.store.FSDirectory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/** Command-line adapter for initializing and querying a workspace index. */
final class CliApp {
    private static final Set<String> COMMANDS = Set.of(
            "init", "refresh", "status", "search-code", "search-config", "get-method",
            "list-web-endpoints", "find-callers", "find-callees", "prewarm");

    private CliApp() {
    }

    static boolean isCommand(String value) {
        return "--help".equals(value) || "help".equals(value) || COMMANDS.contains(value);
    }

    static int run(String[] args) {
        if (args.length == 1 && ("--help".equals(args[0]) || "help".equals(args[0]))) {
            printHelp();
            return 0;
        }
        if (args.length == 0 || !COMMANDS.contains(args[0])) {
            System.err.println("Expected a command. Run `java -jar java-code-db.jar --help` for usage.");
            return 2;
        }

        try {
            String command = args[0];
            Map<String, String> options = parseOptions(args);
            validateOptions(command, options);
            Path workspace = Path.of(options.getOrDefault("workspace", ".")).toAbsolutePath().normalize();
            if (!Files.isDirectory(workspace)) {
                throw new IllegalArgumentException("Workspace is not a directory: " + workspace);
            }

            boolean includeBodies = command.equals("search-code")
                    && booleanOption(options, "include-bodies", false);
            boolean bodyScopeReadOnly = includeBodies && BodyPrewarmCoordinator.awaitScopeReady(workspace,
                    options.getOrDefault("scope", "all"));
            boolean needsIndexUpdates = (includeBodies && !bodyScopeReadOnly)
                    || command.equals("find-callers") || command.equals("find-callees");
            if (!command.equals("prewarm")
                    && (command.equals("init") || command.equals("refresh") || needsIndexUpdates)) {
                BodyPrewarmCoordinator.awaitIdle(workspace);
            }

            if (command.equals("init") || command.equals("refresh")) {
                return refresh(workspace);
            }
            if (command.equals("prewarm")) {
                return prewarm(workspace);
            }
            if (command.equals("status") && !indexExists(workspace)) {
                System.out.println(notInitializedStatus(workspace));
                return 0;
            }

            if (needsIndexUpdates && !IndexService.isCurrentSchema(workspace)) {
                throw new IllegalStateException("Run `init` or `refresh` before this query to build the current index schema");
            }
            try (IndexService index = new IndexService(workspace, !needsIndexUpdates)) {
                System.out.println(invoke(index, command, options));
            }
            return 0;
        } catch (Exception e) {
            System.err.println("JavaCodeDB: " + e.getClass().getSimpleName() + ": " + String.valueOf(e.getMessage()));
            return 2;
        }
    }

    private static int refresh(Path workspace) throws IOException, InterruptedException {
        boolean needsBodyPrewarm;
        String status;
        try (IndexService index = new IndexService(workspace)) {
            index.startBackgroundRefresh();
            index.awaitRefresh();
            status = index.statusJson();
            needsBodyPrewarm = index.needsBodyPrewarm();
        }
        if (status.contains("\"state\":\"failed\"")) {
            System.out.println(status);
            return 1;
        }
        if (needsBodyPrewarm) BodyPrewarmCoordinator.schedule(workspace);
        String finalStatus;
        try (IndexService index = new IndexService(workspace, true)) {
            finalStatus = index.statusJson();
        }
        System.out.println(finalStatus);
        return finalStatus.contains("\"bodyPrewarmState\":\"failed\"") ? 1 : 0;
    }

    private static int prewarm(Path workspace) throws Exception {
        try {
            if (!IndexService.isCurrentSchema(workspace)) {
                throw new IllegalStateException("Run `init` or `refresh` before prewarming method bodies");
            }
            try (BodyPrewarmCoordinator.LockHandle ignored = BodyPrewarmCoordinator.acquire(workspace);
                 IndexService index = new IndexService(workspace)) {
                index.prewarmBodies();
                System.out.println(index.statusJson());
            }
        } catch (Exception e) {
            BodyPrewarmCoordinator.markFailure(workspace, e.getClass().getSimpleName() + ": "
                    + String.valueOf(e.getMessage()));
            throw e;
        }
        return 0;
    }

    private static boolean indexExists(Path workspace) throws IOException {
        Path lucenePath = workspace.resolve(".javacodedb").resolve("lucene");
        if (!Files.isDirectory(lucenePath)) return false;
        try (Directory directory = FSDirectory.open(lucenePath)) {
            return DirectoryReader.indexExists(directory);
        }
    }

    private static String invoke(IndexService index, String command, Map<String, String> options) throws Exception {
        int limit = integerOption(options, "limit", 10);
        int offset = integerOption(options, "offset", 0);
        return switch (command) {
            case "status" -> index.statusJson();
            case "search-code" -> index.searchCode(required(options, "query"),
                    options.getOrDefault("mode", "text"), options.getOrDefault("scope", "all"), limit, offset,
                    booleanOption(options, "include-bodies", false));
            case "search-config" -> index.searchConfig(required(options, "query"), limit, offset);
            case "get-method" -> index.getMethod(required(options, "class-name"), required(options, "method-name"),
                    options.getOrDefault("descriptor", ""), options.getOrDefault("artifact", ""));
            case "list-web-endpoints" -> index.listWebEndpoints(options.getOrDefault("http-method", ""),
                    options.getOrDefault("path-contains", ""), limit, offset);
            case "find-callers" -> index.findCallers(required(options, "class-name"), required(options, "method-name"),
                    options.getOrDefault("descriptor", ""), integerOption(options, "depth", 3), limit, offset);
            case "find-callees" -> index.findCallees(required(options, "class-name"), required(options, "method-name"),
                    options.getOrDefault("descriptor", ""), integerOption(options, "depth", 3), limit, offset);
            default -> throw new IllegalArgumentException("Unknown command: " + command);
        };
    }

    private static Map<String, String> parseOptions(String[] args) {
        Map<String, String> options = new HashMap<>();
        for (int i = 1; i < args.length; i++) {
            String key = args[i];
            if (!key.startsWith("--") || key.length() == 2) {
                throw new IllegalArgumentException("Expected an option, got: " + key);
            }
            if (i + 1 >= args.length || args[i + 1].startsWith("--")) {
                throw new IllegalArgumentException("Missing value for option " + key);
            }
            options.put(key.substring(2), args[++i]);
        }
        return options;
    }

    private static void validateOptions(String command, Map<String, String> options) {
        Set<String> accepted = switch (command) {
            case "init", "refresh", "status", "prewarm" -> Set.of("workspace");
            case "search-code" -> Set.of("workspace", "query", "mode", "scope", "limit", "offset", "include-bodies");
            case "search-config" -> Set.of("workspace", "query", "limit", "offset");
            case "get-method" -> Set.of("workspace", "class-name", "method-name", "descriptor", "artifact");
            case "list-web-endpoints" -> Set.of("workspace", "http-method", "path-contains", "limit", "offset");
            case "find-callers", "find-callees" -> Set.of("workspace", "class-name", "method-name", "descriptor",
                    "depth", "limit", "offset");
            default -> Set.of();
        };
        for (String option : options.keySet()) {
            if (!accepted.contains(option)) {
                throw new IllegalArgumentException("Unknown option for " + command + ": --" + option);
            }
        }
    }

    private static String required(Map<String, String> options, String name) {
        String value = options.get(name);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Required option: --" + name);
        }
        return value;
    }

    private static int integerOption(Map<String, String> options, String name, int fallback) {
        String value = options.get(name);
        if (value == null) return fallback;
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Option --" + name + " must be an integer");
        }
    }

    private static boolean booleanOption(Map<String, String> options, String name, boolean fallback) {
        String value = options.get(name);
        if (value == null) return fallback;
        if (value.equalsIgnoreCase("true")) return true;
        if (value.equalsIgnoreCase("false")) return false;
        throw new IllegalArgumentException("Option --" + name + " must be true or false");
    }

    private static String notInitializedStatus(Path workspace) {
        return "{\"workspace\":" + quote(workspace.toString())
                + ",\"indexDirectory\":" + quote(workspace.resolve(".javacodedb").toString())
                + ",\"state\":\"not_initialized\",\"classesIndexed\":0,\"methodsIndexed\":0,\"resourcesIndexed\":0}";
    }

    private static String quote(String value) {
        StringBuilder escaped = new StringBuilder("\"");
        for (int i = 0; i < value.length(); i++) {
            char character = value.charAt(i);
            switch (character) {
                case '"' -> escaped.append("\\\"");
                case '\\' -> escaped.append("\\\\");
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

    private static void printHelp() {
        System.out.println("""
                JavaCodeDB local CLI

                Usage: java -jar java-code-db.jar <command> [options]
                Workspace defaults to the current directory. Symbol/config queries are read-only; full-body and call-graph queries update the index lazily.

                Commands:
                  init                         Build or incrementally update the current workspace index
                  refresh                      Incrementally update the current workspace index
                  status                       Print index status as JSON
                  search-code --query TEXT     Search ASM symbols; --include-bodies true indexes method bodies in --scope for full-text search
                  search-config --query TEXT   Search application configuration and templates
                  get-method --class-name NAME --method-name NAME [--descriptor DESC] [--artifact PATH]
                  list-web-endpoints           List discovered web endpoints
                  find-callers --class-name NAME --method-name NAME [--depth N]
                  find-callees --class-name NAME --method-name NAME [--depth N]
                  prewarm                      Run or resume staged method-body indexing

                Common options: --workspace PATH, --limit N, --offset N
                Body indexing starts in the background after init/refresh; status reports staged progress.
                """);
    }
}
