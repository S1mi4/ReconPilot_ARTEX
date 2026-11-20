package io.javacodedb;

import io.modelcontextprotocol.json.McpJsonDefaults;
import io.modelcontextprotocol.server.McpServer;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.server.transport.StdioServerTransportProvider;
import io.modelcontextprotocol.spec.McpSchema;

import java.util.List;
import java.util.Map;

final class McpServerApp implements AutoCloseable {
    private final IndexService indexService;
    private McpSyncServer server;

    McpServerApp(IndexService indexService) {
        this.indexService = indexService;
    }

    void start() {
        StdioServerTransportProvider transport = new StdioServerTransportProvider(McpJsonDefaults.getMapper());
        var builder = McpServer.sync(transport)
                .serverInfo("javacodedb", "0.1.0")
                .capabilities(McpSchema.ServerCapabilities.builder().tools(false).build())
                .toolCall(tool("get_index_status", "Return workspace index state, symbol counts, staged body-prewarm phase/progress, and recent indexing issues.",
                                objectSchema(Map.of(), List.of())),
                        (exchange, request) -> result(indexService.statusJson()))
                .toolCall(tool("refresh_index", "Update the symbol index, then prewarm method bodies in the background (application classes before dependencies).",
                                objectSchema(Map.of(), List.of())),
                        (exchange, request) -> result(indexService.requestRefresh()))
                .toolCall(tool("search_code", "Search ASM symbols by default. Initialization prewarms decompiled bodies in the background (application first, then dependencies). Set includeBodies=true to wait for and search bodies in the requested scope; the response reports whether that scope is complete.",
                                objectSchema(Map.of(
                                        "query", stringSchema("Text or Lucene query syntax to search for."),
                                        "mode", enumStringSchema("Search mode; defaults to text.", List.of("text", "substring", "regex")),
                                        "scope", enumStringSchema("Artifact scope; defaults to all.", List.of("all", "application", "dependency")),
                                        "includeBodies", booleanSchema("Wait for background body indexing if needed, then search method bodies in the requested scope (all by default). The result includes bodySearchComplete."),
                                        "limit", pageSizeSchema(),
                                        "offset", integerSchema("Result offset, capped at 1000.")), List.of("query"))),
                        (exchange, request) -> invoke(() -> indexService.searchCode(
                                stringArg(request.arguments(), "query", null),
                                stringArg(request.arguments(), "mode", "text"),
                                stringArg(request.arguments(), "scope", "all"),
                                intArg(request.arguments(), "limit", 10),
                                intArg(request.arguments(), "offset", 0),
                                booleanArg(request.arguments(), "includeBodies", false))))
                .toolCall(tool("search_config", "Search indexed application configuration files and server-side templates such as YAML, XML, JSP, and FreeMarker.",
                                objectSchema(Map.of(
                                        "query", stringSchema("Configuration key, value, filename, or Lucene query."),
                                        "limit", pageSizeSchema(),
                                        "offset", integerSchema("Result offset, capped at 1000.")), List.of("query"))),
                        (exchange, request) -> invoke(() -> indexService.searchConfig(
                                stringArg(request.arguments(), "query", null),
                                intArg(request.arguments(), "limit", 10),
                                intArg(request.arguments(), "offset", 0))))
                .toolCall(tool("get_method", "Fetch a decompiled method body by class and method name; optionally disambiguate with JVM descriptor and artifact path.",
                                objectSchema(Map.of(
                                        "className", stringSchema("Fully qualified Java class name."),
                                        "methodName", stringSchema("Java method name, or <init> for a constructor."),
                                        "descriptor", stringSchema("Optional JVM descriptor, such as (Ljava/lang/String;)V."),
                                        "artifact", stringSchema("Optional workspace-relative artifact path.")),
                                        List.of("className", "methodName"))),
                        (exchange, request) -> invoke(() -> indexService.getMethod(
                                stringArg(request.arguments(), "className", null),
                                stringArg(request.arguments(), "methodName", null),
                                stringArg(request.arguments(), "descriptor", ""),
                                stringArg(request.arguments(), "artifact", ""))));
        builder
                .toolCall(tool("get_class_source", "Fetch a bounded, line-numbered range by class name or an exact artifact and archive entry pair.",
                                objectSchema(Map.of(
                                        "className", stringSchema("Fully qualified Java class name."),
                                        "artifact", stringSchema("Optional workspace-relative artifact path."),
                                        "entry", stringSchema("Optional exact class archive entry path."),
                                        "startLine", integerSchema("First source line; defaults to 1."),
                                        "endLine", integerSchema("Last source line; defaults to 200.")), List.of())),
                        (exchange, request) -> invoke(() -> indexService.getClassSource(
                                stringArg(request.arguments(), "className", null),
                                stringArg(request.arguments(), "artifact", ""),
                                stringArg(request.arguments(), "entry", ""),
                                intArg(request.arguments(), "startLine", 1),
                                intArg(request.arguments(), "endLine", 200))))
                .toolCall(tool("list_classes", "List indexed classes in stable pages with their artifact and archive entry paths. Filter by application or dependency scope.",
                                objectSchema(Map.of("limit", pageSizeSchema(),
                                        "offset", Map.of("type", "integer", "description", "Result offset, capped at 50000.",
                                                "minimum", 0, "maximum", 50_000),
                                        "scope", enumStringSchema("Class scope; defaults to all.", List.of("all", "application", "dependency"))), List.of())),
                        (exchange, request) -> invoke(() -> indexService.listClasses(
                                intArg(request.arguments(), "limit", 50),
                                intArg(request.arguments(), "offset", 0),
                                stringArg(request.arguments(), "scope", "all"))));
        builder
                .toolCall(tool("list_web_endpoints", "List Spring MVC annotations, @WebServlet endpoints, and web.xml servlet mappings.",
                                objectSchema(Map.of(
                                        "httpMethod", stringSchema("Optional HTTP method such as GET or POST."),
                                        "pathContains", stringSchema("Optional case-insensitive route substring."),
                                        "limit", pageSizeSchema(),
                                        "offset", integerSchema("Result offset, capped at 1000.")), List.of())),
                        (exchange, request) -> invoke(() -> indexService.listWebEndpoints(
                                stringArg(request.arguments(), "httpMethod", ""),
                                stringArg(request.arguments(), "pathContains", ""),
                                intArg(request.arguments(), "limit", 10),
                                intArg(request.arguments(), "offset", 0))))
                .toolCall(tool("find_callers", "Find direct and CHA possible callers of a Java method, with bounded multi-hop traversal.",
                                graphSchema()),
                        (exchange, request) -> invoke(() -> indexService.findCallers(
                                stringArg(request.arguments(), "className", null),
                                stringArg(request.arguments(), "methodName", null),
                                stringArg(request.arguments(), "descriptor", ""),
                                intArg(request.arguments(), "depth", 3),
                                intArg(request.arguments(), "limit", 10),
                                intArg(request.arguments(), "offset", 0))))
                .toolCall(tool("find_callees", "Find direct and CHA possible callees of a Java method, with bounded multi-hop traversal.",
                                graphSchema()),
                        (exchange, request) -> invoke(() -> indexService.findCallees(
                                stringArg(request.arguments(), "className", null),
                                stringArg(request.arguments(), "methodName", null),
                                stringArg(request.arguments(), "descriptor", ""),
                                intArg(request.arguments(), "depth", 3),
                                intArg(request.arguments(), "limit", 10),
                                intArg(request.arguments(), "offset", 0))));
        server = builder.build();
    }

    private static McpSchema.Tool tool(String name, String description, Map<String, Object> schema) {
        return McpSchema.Tool.builder(name, schema).description(description).build();
    }

    private static Map<String, Object> objectSchema(Map<String, Object> properties, List<String> required) {
        return Map.of("type", "object", "properties", properties, "required", required);
    }

    private static Map<String, Object> stringSchema(String description) {
        return Map.of("type", "string", "description", description);
    }

    private static Map<String, Object> enumStringSchema(String description, List<String> options) {
        return Map.of("type", "string", "description", description, "enum", options);
    }

    private static Map<String, Object> integerSchema(String description) {
        return Map.of("type", "integer", "description", description, "minimum", 0, "maximum", 1_000);
    }

    private static Map<String, Object> booleanSchema(String description) {
        return Map.of("type", "boolean", "description", description);
    }

    private static Map<String, Object> pageSizeSchema() {
        return Map.of("type", "integer", "description", "Page size, from 1 to 50.", "minimum", 1, "maximum", 50);
    }

    private static Map<String, Object> graphSchema() {
        return objectSchema(Map.of(
                "className", stringSchema("Fully qualified Java class name."),
                "methodName", stringSchema("Java method name, or <init> for a constructor."),
                "descriptor", stringSchema("Optional JVM descriptor."),
                "depth", Map.of("type", "integer", "description", "Traversal depth from 1 to 5; defaults to 3.",
                        "minimum", 1, "maximum", 5),
                "limit", pageSizeSchema(),
                "offset", integerSchema("Result offset, capped at 1000.")), List.of("className", "methodName"));
    }

    private static String stringArg(Map<String, Object> args, String name, String fallback) {
        Object value = args == null ? null : args.get(name);
        return value == null ? fallback : value.toString();
    }

    private static int intArg(Map<String, Object> args, String name, int fallback) {
        Object value = args == null ? null : args.get(name);
        if (value instanceof Number number) return number.intValue();
        if (value instanceof String text) {
            try { return Integer.parseInt(text); } catch (NumberFormatException ignored) { return fallback; }
        }
        return fallback;
    }

    private static boolean booleanArg(Map<String, Object> args, String name, boolean fallback) {
        Object value = args == null ? null : args.get(name);
        if (value instanceof Boolean bool) return bool;
        if (value instanceof String text) return Boolean.parseBoolean(text);
        return fallback;
    }

    private static McpSchema.CallToolResult result(String text) {
        return McpSchema.CallToolResult.builder()
                .content(List.of(new McpSchema.TextContent(text)))
                .build();
    }

    private static McpSchema.CallToolResult invoke(CheckedSupplier action) {
        try {
            return result(action.get());
        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                    .content(List.of(new McpSchema.TextContent("{\"error\":"
                            + quoteJson(e.getClass().getSimpleName() + ": " + String.valueOf(e.getMessage())) + "}")))
                    .isError(true)
                    .build();
        }
    }

    @FunctionalInterface
    private interface CheckedSupplier {
        String get() throws Exception;
    }

    private static String quoteJson(String value) {
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

    @Override
    public void close() {
        if (server != null) {
            server.close();
        }
    }
}
