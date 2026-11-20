package io.javacodedb;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.ConstructorDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import org.apache.lucene.document.Document;
import org.apache.lucene.document.Field;
import org.apache.lucene.document.StringField;
import org.apache.lucene.document.TextField;
import org.benf.cfr.reader.api.CfrDriver;
import org.benf.cfr.reader.api.OutputSinkFactory;
import org.benf.cfr.reader.api.SinkReturns;
import org.objectweb.asm.AnnotationVisitor;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.signature.SignatureReader;
import org.objectweb.asm.signature.SignatureVisitor;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

final class BytecodeIndexer {
    private static final int MAX_SOURCE_CHARS = 2_000_000;
    private static final int METHOD_SOURCE_LOOKUP_THRESHOLD = 16;
    private static final ThreadLocal<JavaParser> METHOD_SOURCE_PARSERS = ThreadLocal.withInitial(() ->
            new JavaParser(new ParserConfiguration()
                    .setLanguageLevel(ParserConfiguration.LanguageLevel.RAW)
                    .setAttributeComments(false)));

    IndexedClass indexSymbols(ArtifactScanner.ClassEntry entry, String hash) throws Exception {
        return indexUncached(entry, hash, null, false, false, null);
    }

    IndexedClass indexGraph(ArtifactScanner.ClassEntry entry, String hash, ClassIndexCache cache,
                            IndexedClass cached) throws Exception {
        if (cached != null && cached.graphIndexed()) return cached;
        IndexedClass indexed = indexUncached(entry, hash, cached, true, false, null);
        cache.put(indexed);
        return indexed;
    }

    IndexedClass indexWithBodies(ArtifactScanner.ClassEntry entry, String hash, DecompileWorkerPool workers,
                                 ClassIndexCache cache) throws Exception {
        IndexedClass cached = cache.get(hash, entry);
        return indexWithBodies(entry, hash, workers, cache, cached);
    }

    IndexedClass indexWithBodies(ArtifactScanner.ClassEntry entry, String hash, DecompileWorkerPool workers,
                                 ClassIndexCache cache, IndexedClass cached) throws Exception {
        if (cached != null && cached.bodyIndexed() && cached.graphIndexed()) {
            return cached;
        }
        IndexedClass indexed = indexUncached(entry, hash, cached, true, true, workers);
        cache.put(indexed);
        return indexed;
    }

    private IndexedClass indexUncached(ArtifactScanner.ClassEntry entry, String hash, IndexedClass cached,
                                       boolean includeCode, boolean includeBodies,
                                       DecompileWorkerPool workers) throws Exception {
        int majorVersion = entry.bytes().length >= 8
                ? (((entry.bytes()[6] & 0xff) << 8) | (entry.bytes()[7] & 0xff)) : -1;
        if (entry.bytes().length < 10 || (entry.bytes()[0] & 0xff) != 0xCA
                || (entry.bytes()[1] & 0xff) != 0xFE || (entry.bytes()[2] & 0xff) != 0xBA
                || (entry.bytes()[3] & 0xff) != 0xBE) {
            return IndexedClass.invalid(entry, hash, majorVersion, "Invalid class-file header", true, includeBodies);
        }

        ClassMetadata metadata;
        try {
            metadata = cached != null && cached.error() == null && (!includeCode || cached.graphIndexed())
                    ? new ClassMetadata(cached.className(), cached.packageName(), cached.access(), cached.superName(),
                    cached.interfaces(), cached.annotations(), cached.methods(), cached.endpoints(), cached.referencedTypes())
                    : parseClass(entry.bytes(), includeCode);
        } catch (RuntimeException e) {
            return IndexedClass.invalid(entry, hash, majorVersion,
                    "Unsupported or malformed bytecode: " + e.getMessage(), true, includeBodies);
        }

        List<MethodRecord> methods = new ArrayList<>();
        String source = cached != null && cached.bodyIndexed() ? cached.source() : "";
        Map<String, MethodRecord> cachedBodies = new HashMap<>();
        if (cached != null && cached.bodyIndexed()) {
            for (MethodRecord cachedMethod : cached.methodRecords()) {
                cachedBodies.put(methodKey(cachedMethod.name(), cachedMethod.descriptor()), cachedMethod);
            }
        }
        MethodSourceLookup methodSources = null;
        if (includeBodies) {
            if (cached == null || !cached.bodyIndexed()) {
                source = workers.decompile(entry.bytes());
                methodSources = indexMethodSources(extractMethods(source));
            }
        }
        for (MethodMetadata method : metadata.methods()) {
            String body = "";
            if (cached != null && cached.bodyIndexed()) {
                MethodRecord prior = cachedBodies.get(methodKey(method.name(), method.descriptor()));
                if (prior != null) body = prior.source();
            } else if (includeBodies) {
                MethodSource methodSource = findSource(method, methodSources);
                if (methodSource != null) body = methodSource.source();
            }
            methods.add(new MethodRecord(method.name(), method.descriptor(), method.signature(), method.calls(),
                    method.endpoints(), body));
        }
        return new IndexedClass(entry, hash, metadata.className(), metadata.packageName(), majorVersion,
                metadata.access(), metadata.superName(), metadata.interfaces(), metadata.annotations(),
                metadata.methods(), methods, metadata.endpoints(), metadata.referencedTypes(), source, null,
                includeCode, includeBodies || cached != null && cached.bodyIndexed());
    }

    private static String methodKey(String name, String descriptor) {
        return name + "\u0000" + descriptor;
    }

    private static ClassMetadata parseClass(byte[] bytecode, boolean includeCode) {
        ClassMetadataBuilder builder = new ClassMetadataBuilder();
        int flags = ClassReader.SKIP_FRAMES | (includeCode ? 0 : ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG);
        new ClassReader(bytecode).accept(builder, flags);
        return builder.build();
    }

    static String decompileClassFile(Path input) throws Exception {
        StringBuilder result = new StringBuilder();
        OutputSinkFactory sinkFactory = new OutputSinkFactory() {
                    @Override
                    public List<SinkClass> getSupportedSinks(SinkType sinkType, Collection<SinkClass> available) {
                        if (sinkType == SinkType.JAVA && available.contains(SinkClass.DECOMPILED)) {
                            return List.of(SinkClass.DECOMPILED);
                        }
                        return List.of(SinkClass.STRING);
                    }

                    @Override
                    @SuppressWarnings("unchecked")
                    public <T> Sink<T> getSink(SinkType sinkType, SinkClass sinkClass) {
                        if (sinkType == SinkType.JAVA && sinkClass == SinkClass.DECOMPILED) {
                            return (Sink<T>) (Sink<SinkReturns.Decompiled>) value -> {
                                if (result.length() < MAX_SOURCE_CHARS) {
                                    result.append(value.getJava(), 0,
                                            Math.min(value.getJava().length(), MAX_SOURCE_CHARS - result.length()));
                                }
                            };
                        }
                        if (sinkType == SinkType.JAVA && sinkClass == SinkClass.STRING) {
                            return (Sink<T>) (Sink<String>) value -> {
                                if (result.length() < MAX_SOURCE_CHARS) {
                                    result.append(value, 0,
                                            Math.min(value.length(), MAX_SOURCE_CHARS - result.length()));
                                }
                            };
                        }
                        return value -> { };
                    }
                };
        CfrDriver driver = new CfrDriver.Builder()
                .withOptions(Map.of("silent", "true", "comments", "false", "showversion", "false"))
                .withOutputSink(sinkFactory)
                .build();
        driver.analyse(List.of(input.toString()));
        return result.toString();
    }

    private static List<MethodSource> extractMethods(String source) {
        if (source.isBlank()) {
            return List.of();
        }
        try {
            var parseResult = METHOD_SOURCE_PARSERS.get().parse(source);
            if (!parseResult.isSuccessful() || parseResult.getResult().isEmpty()) {
                return List.of();
            }
            CompilationUnit unit = parseResult.getResult().orElseThrow();
            List<MethodSource> methods = new ArrayList<>();
            unit.walk(Node.TreeTraversal.PREORDER, node -> {
                if (node instanceof MethodDeclaration declaration) {
                    methods.add(new MethodSource(declaration.getNameAsString(), declaration.getParameters().stream()
                            .map(parameter -> parameter.getType().asString()).toList(), declaration.toString()));
                } else if (node instanceof ConstructorDeclaration declaration) {
                    methods.add(new MethodSource("<init>", declaration.getParameters().stream()
                            .map(parameter -> parameter.getType().asString()).toList(), declaration.toString()));
                }
            });
            return methods;
        } catch (Exception e) {
            return List.of();
        }
    }

    private static MethodSourceLookup indexMethodSources(List<MethodSource> sources) {
        if (sources.size() < METHOD_SOURCE_LOOKUP_THRESHOLD) {
            return new MethodSourceLookup(sources, null, null);
        }
        Map<MethodSignature, MethodSource> bySignature = new HashMap<>();
        Map<MethodNameArity, List<MethodSource>> byNameAndArity = new HashMap<>();
        for (MethodSource source : sources) {
            List<String> parameterTypes = source.parameterTypes().stream().map(BytecodeIndexer::simpleType).toList();
            bySignature.putIfAbsent(new MethodSignature(source.name(), parameterTypes), source);
            byNameAndArity.computeIfAbsent(new MethodNameArity(source.name(), parameterTypes.size()),
                    ignored -> new ArrayList<>()).add(source);
        }
        byNameAndArity.replaceAll((key, value) -> List.copyOf(value));
        return new MethodSourceLookup(sources, bySignature, byNameAndArity);
    }

    private static MethodSource findSource(MethodMetadata method, MethodSourceLookup sources) {
        if (sources.bySignature() == null) {
            return findSourceLinear(method, sources.sources());
        }
        String sourceName = method.name().equals("<init>") ? "<init>" : method.name();
        List<String> parameterTypes = java.util.Arrays.stream(Type.getArgumentTypes(method.descriptor()))
                .map(Type::getClassName).map(BytecodeIndexer::simpleType).toList();
        MethodSource exact = sources.bySignature().get(new MethodSignature(sourceName, parameterTypes));
        if (exact != null) return exact;
        List<MethodSource> sameArity = sources.byNameAndArity()
                .get(new MethodNameArity(sourceName, parameterTypes.size()));
        return sameArity != null && sameArity.size() == 1 ? sameArity.getFirst() : null;
    }

    private static MethodSource findSourceLinear(MethodMetadata method, List<MethodSource> sources) {
        String sourceName = method.name().equals("<init>") ? "<init>" : method.name();
        List<String> parameterTypes = java.util.Arrays.stream(Type.getArgumentTypes(method.descriptor()))
                .map(Type::getClassName).toList();
        List<MethodSource> sameArity = new ArrayList<>();
        for (MethodSource candidate : sources) {
            if (!candidate.name().equals(sourceName) || candidate.parameterTypes().size() != parameterTypes.size()) {
                continue;
            }
            sameArity.add(candidate);
            boolean sameTypes = true;
            for (int i = 0; i < parameterTypes.size(); i++) {
                if (!simpleType(parameterTypes.get(i)).equals(simpleType(candidate.parameterTypes().get(i)))) {
                    sameTypes = false;
                    break;
                }
            }
            if (sameTypes) {
                return candidate;
            }
        }
        return sameArity.size() == 1 ? sameArity.getFirst() : null;
    }

    private static String simpleType(String name) {
        String normalized = name.replace("...", "[]").replace(" ", "");
        int generic = normalized.indexOf('<');
        if (generic >= 0) normalized = normalized.substring(0, generic);
        int dot = Math.max(normalized.lastIndexOf('.'), normalized.lastIndexOf('$'));
        return normalized.substring(dot + 1);
    }

    private static Document classDocument(IndexedClass indexed, boolean includeBodies) {
        Document document = baseDocument(indexed, "class", indexed.id());
        addText(document, "className", indexed.className());
        addExact(document, "classNameExact", indexed.className());
        addText(document, "packageName", indexed.packageName());
        String annotations = String.join(" ", indexed.annotations());
        addText(document, "annotations", annotations);
        addTrigramContent(document, indexed.className() + " " + indexed.packageName() + " " + annotations);
        addExact(document, "graphIndexed", Boolean.toString(indexed.graphIndexed()));
        addExact(document, "bodyIndexed", Boolean.toString(includeBodies && indexed.bodyIndexed()));
        addExact(document, "superName", indexed.superName());
        indexed.interfaces().forEach(name -> addExact(document, "interfaceName", name));
        indexed.referencedTypes().forEach(name -> addExact(document, "referenceType", name));
        indexed.endpoints().forEach(endpoint -> {
            addText(document, "endpointRoute", endpoint.route());
            addExact(document, "endpointRouteExact", endpoint.route());
            addExact(document, "httpMethod", endpoint.httpMethod());
            addExact(document, "endpointHandler", endpoint.methodName());
        });
        addExact(document, "classVersion", Integer.toString(indexed.majorVersion()));
        addExact(document, "interfaceClass", Boolean.toString((indexed.access() & Opcodes.ACC_INTERFACE) != 0));
        addExact(document, "abstractClass", Boolean.toString((indexed.access() & Opcodes.ACC_ABSTRACT) != 0));
        if (indexed.error() != null) {
            addText(document, "error", indexed.error());
            if (indexed.majorVersion() > Runtime.version().feature() + 44) {
                addExact(document, "unsupportedVersion", "true");
            }
        } else if (includeBodies && indexed.bodyIndexed() && indexed.source().isBlank()
                && !indexed.methodRecords().isEmpty()) {
            addExact(document, "decompilerFailed", "true");
        }
        return document;
    }

    static List<Document> toDocuments(IndexedClass indexed, boolean includeBodies) {
        List<Document> documents = new ArrayList<>();
        documents.add(classDocument(indexed, includeBodies));
        for (MethodRecord method : indexed.methodRecords()) {
            String methodId = indexed.id() + "#" + method.name() + method.descriptor();
            Document document = baseDocument(indexed, "method", methodId);
            addText(document, "className", indexed.className());
            addExact(document, "classNameExact", indexed.className());
            addText(document, "packageName", indexed.packageName());
            addText(document, "methodName", method.name());
            addExact(document, "methodNameExact", method.name());
            addExact(document, "descriptor", method.descriptor());
            addText(document, "signature", method.signature());
            addExact(document, "graphIndexed", Boolean.toString(indexed.graphIndexed()));
            addExact(document, "bodyIndexed", Boolean.toString(includeBodies && indexed.bodyIndexed()));
            String body = includeBodies && indexed.bodyIndexed() ? method.source() : "";
            addText(document, "content", body);
            addTrigramContent(document, indexed.className() + " " + indexed.packageName() + " "
                    + method.signature() + (body.isBlank() ? "" : " " + body));
            addExact(document, "methodKey", indexed.className() + "#" + method.name() + method.descriptor());
            method.calls().forEach(call -> {
                addExact(document, "callTarget", call.target());
                addExact(document, "callKind", call.kind());
            });
            method.endpoints().forEach(endpoint -> {
                addText(document, "endpointRoute", endpoint.route());
                addExact(document, "endpointRouteExact", endpoint.route());
                addExact(document, "httpMethod", endpoint.httpMethod());
                addExact(document, "endpointHandler", endpoint.methodName());
            });
            documents.add(document);
        }
        return documents;
    }

    private static Document baseDocument(IndexedClass indexed, String type, String recordId) {
        Document document = new Document();
        addExact(document, "recordId", recordId);
        addExact(document, "classId", indexed.id());
        addExact(document, "docType", type);
        addExact(document, "artifact", indexed.entry().artifact());
        addExact(document, "entry", indexed.entry().entry());
        addExact(document, "application", Boolean.toString(indexed.entry().application()));
        addExact(document, "hash", indexed.hash());
        addExact(document, "byteSize", Integer.toString(indexed.entry().bytes().length));
        addExact(document, "majorVersion", Integer.toString(indexed.majorVersion()));
        addExact(document, "interfaceClass", Boolean.toString((indexed.access() & Opcodes.ACC_INTERFACE) != 0));
        addExact(document, "abstractClass", Boolean.toString((indexed.access() & Opcodes.ACC_ABSTRACT) != 0));
        return document;
    }

    private static void addExact(Document document, String field, String value) {
        if (value != null && !value.isBlank()) {
            document.add(new StringField(field, value, Field.Store.YES));
        }
    }

    private static void addText(Document document, String field, String value) {
        if (value != null && !value.isBlank()) {
            document.add(new TextField(field, value, Field.Store.YES));
        }
    }

    private static void addTrigramContent(Document document, String value) {
        if (value != null && !value.isBlank()) {
            document.add(new TextField("trigramContent", value.toLowerCase(Locale.ROOT), Field.Store.NO));
        }
    }

    record IndexedClass(ArtifactScanner.ClassEntry entry, String hash, String className, String packageName,
                        int majorVersion, int access, String superName, List<String> interfaces,
                        List<String> annotations, List<MethodMetadata> methods, List<MethodRecord> methodRecords,
                        List<Endpoint> endpoints, Set<String> referencedTypes, String source, String error,
                        boolean graphIndexed, boolean bodyIndexed) {
        String id() {
            return entry.id();
        }

        static IndexedClass invalid(ArtifactScanner.ClassEntry entry, String hash, int version, String error,
                                    boolean graphIndexed, boolean bodyIndexed) {
            return new IndexedClass(entry, hash, "", "", version, 0, "", List.of(), List.of(), List.of(),
                    List.of(), List.of(), Set.of(), "", error, graphIndexed, bodyIndexed);
        }
    }

    record MethodMetadata(String name, String descriptor, String signature, List<CallEdge> calls,
                          List<Endpoint> endpoints) {
    }

    record MethodRecord(String name, String descriptor, String signature, List<CallEdge> calls,
                        List<Endpoint> endpoints, String source) {
    }

    record CallEdge(String target, String kind) {
    }

    record Endpoint(String route, String httpMethod, String className, String methodName, String descriptor) {
    }

    private record MethodSource(String name, List<String> parameterTypes, String source) {
    }

    private record MethodSignature(String name, List<String> parameterTypes) {
    }

    private record MethodNameArity(String name, int arity) {
    }

    private record MethodSourceLookup(List<MethodSource> sources,
                                      Map<MethodSignature, MethodSource> bySignature,
                                      Map<MethodNameArity, List<MethodSource>> byNameAndArity) {
    }

    private record ClassMetadata(String className, String packageName, int access, String superName,
                                 List<String> interfaces, List<String> annotations, List<MethodMetadata> methods,
                                 List<Endpoint> endpoints, Set<String> referencedTypes) {
    }

    private static final class ClassMetadataBuilder extends ClassVisitor {
        private String className = "";
        private String packageName = "";
        private int access;
        private String superName = "";
        private List<String> interfaces = List.of();
        private final List<String> annotations = new ArrayList<>();
        private final List<MethodMetadata> methods = new ArrayList<>();
        private final List<Endpoint> endpoints = new ArrayList<>();
        private final Set<String> referencedTypes = new java.util.LinkedHashSet<>();
        private final List<String> classPaths = new ArrayList<>();
        private final List<String> servletPaths = new ArrayList<>();

        private ClassMetadataBuilder() {
            super(Opcodes.ASM9);
        }

        @Override
        public void visit(int version, int access, String name, String signature, String superName, String[] interfaces) {
            this.className = name.replace('/', '.');
            int separator = name.lastIndexOf('/');
            this.packageName = separator < 0 ? "" : name.substring(0, separator).replace('/', '.');
            this.access = access;
            this.superName = superName == null ? "" : superName.replace('/', '.');
            this.interfaces = interfaces == null ? List.of()
                    : java.util.Arrays.stream(interfaces).map(it -> it.replace('/', '.')).toList();
            addInternalName(superName);
            if (interfaces != null) java.util.Arrays.stream(interfaces).forEach(this::addInternalName);
            addSignature(signature, true);
        }

        @Override
        public AnnotationVisitor visitAnnotation(String descriptor, boolean visible) {
            String annotationName = Type.getType(descriptor).getClassName();
            annotations.add(annotationName);
            referencedTypes.add(annotationName);
            return new AnnotationValues(values -> {
                if (annotationName.endsWith(".RequestMapping")) {
                    classPaths.addAll(mappingPaths(values));
                } else if (annotationName.endsWith(".WebServlet")) {
                    servletPaths.addAll(values.getOrDefault("urlPatterns", values.getOrDefault("value", List.of())));
                }
            });
        }

        @Override
        public void visitOuterClass(String owner, String name, String descriptor) {
            addInternalName(owner);
            addDescriptor(descriptor);
        }

        @Override
        public void visitInnerClass(String name, String outerName, String innerName, int access) {
            addInternalName(name);
            addInternalName(outerName);
        }

        @Override
        public void visitNestHost(String nestHost) {
            addInternalName(nestHost);
        }

        @Override
        public void visitNestMember(String nestMember) {
            addInternalName(nestMember);
        }

        @Override
        public void visitPermittedSubclass(String permittedSubclass) {
            addInternalName(permittedSubclass);
        }

        @Override
        public org.objectweb.asm.RecordComponentVisitor visitRecordComponent(String name, String descriptor,
                                                                               String signature) {
            addDescriptor(descriptor);
            addSignature(signature, false);
            return new org.objectweb.asm.RecordComponentVisitor(Opcodes.ASM9) {
                @Override
                public AnnotationVisitor visitAnnotation(String annotationDescriptor, boolean visible) {
                    referencedTypes.add(Type.getType(annotationDescriptor).getClassName());
                    return null;
                }
            };
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
            String display = Type.getReturnType(descriptor).getClassName() + " " + name +
                    "(" + String.join(", ", java.util.Arrays.stream(Type.getArgumentTypes(descriptor))
                    .map(Type::getClassName).toList()) + ")";
            List<CallEdge> calls = new ArrayList<>();
            addDescriptor(descriptor);
            addSignature(signature, true);
            if (exceptions != null) java.util.Arrays.stream(exceptions).forEach(this::addInternalName);
            List<Endpoint> methodEndpoints = new ArrayList<>();
            methods.add(new MethodMetadata(name, descriptor, display, calls, methodEndpoints));
            return new MethodVisitor(Opcodes.ASM9) {
                @Override
                public void visitMethodInsn(int opcode, String owner, String methodName, String methodDescriptor,
                                            boolean isInterface) {
                    addInternalName(owner);
                    addDescriptor(methodDescriptor);
                    String kind = switch (opcode) {
                        case Opcodes.INVOKESTATIC -> "static";
                        case Opcodes.INVOKESPECIAL -> "special";
                        case Opcodes.INVOKEINTERFACE -> "interface";
                        default -> "virtual";
                    };
                    calls.add(new CallEdge(owner.replace('/', '.') + "#" + methodName + methodDescriptor, kind));
                }

                @Override
                public void visitInvokeDynamicInsn(String dynamicName, String dynamicDescriptor,
                                                   org.objectweb.asm.Handle bootstrapMethodHandle, Object... bootstrapArguments) {
                    addDescriptor(dynamicDescriptor);
                    for (Object argument : bootstrapArguments) {
                        if (argument instanceof org.objectweb.asm.Handle handle) {
                            addInternalName(handle.getOwner());
                            addDescriptor(handle.getDesc());
                            calls.add(new CallEdge(handle.getOwner().replace('/', '.') + "#" + handle.getName()
                                    + handle.getDesc(), "dynamic"));
                        }
                    }
                }

                @Override
                public void visitTypeInsn(int opcode, String type) {
                    if (type.startsWith("[")) addDescriptor(type);
                    else addInternalName(type);
                }

                @Override
                public void visitFieldInsn(int opcode, String owner, String fieldName, String fieldDescriptor) {
                    addInternalName(owner);
                    addDescriptor(fieldDescriptor);
                }

                @Override
                public void visitMultiANewArrayInsn(String descriptor, int dimensions) {
                    addDescriptor(descriptor);
                }

                @Override
                public void visitLdcInsn(Object value) {
                    if (value instanceof Type type) addType(type);
                }

                @Override
                public void visitTryCatchBlock(org.objectweb.asm.Label start, org.objectweb.asm.Label end,
                                               org.objectweb.asm.Label handler, String type) {
                    addInternalName(type);
                }

                @Override
                public AnnotationVisitor visitAnnotation(String annotationDescriptor, boolean visible) {
                    String annotationName = Type.getType(annotationDescriptor).getClassName();
                    referencedTypes.add(annotationName);
                    return new AnnotationValues(values -> {
                        String mappingName = annotationName.substring(annotationName.lastIndexOf('.') + 1);
                        List<String> paths = mappingPaths(values);
                        if (isSpringMapping(mappingName)) {
                            List<String> httpMethods = springHttpMethods(mappingName, values);
                            for (String base : classPaths.isEmpty() ? List.of("") : classPaths) {
                                for (String path : paths.isEmpty() ? List.of("") : paths) {
                                    for (String httpMethod : httpMethods) {
                                        String route = joinRoute(base, path);
                                        if (!route.isBlank()) {
                                            Endpoint endpoint = new Endpoint(route, httpMethod, className, name, descriptor);
                                            methodEndpoints.add(endpoint);
                                            endpoints.add(endpoint);
                                        }
                                    }
                                }
                            }
                        }
                    });
                }
            };
        }

        ClassMetadata build() {
            if (!servletPaths.isEmpty()) {
                boolean hasHttpHandlers = false;
                for (MethodMetadata method : methods) {
                    if (method.name().startsWith("do") && method.name().length() > 2) {
                        hasHttpHandlers = true;
                        String httpMethod = method.name().substring(2).toUpperCase(Locale.ROOT);
                        for (String route : servletPaths) {
                            Endpoint endpoint = new Endpoint(route, httpMethod, className, method.name(), method.descriptor());
                            method.endpoints().add(endpoint);
                            endpoints.add(endpoint);
                        }
                    }
                }
                if (!hasHttpHandlers) {
                    for (String route : servletPaths) {
                        endpoints.add(new Endpoint(route, "ANY", className, "service", ""));
                    }
                }
            }
            return new ClassMetadata(className, packageName, access, superName, interfaces, annotations, methods,
                    endpoints, Set.copyOf(referencedTypes));
        }

        @Override
        public org.objectweb.asm.FieldVisitor visitField(int access, String name, String descriptor,
                                                          String signature, Object value) {
            addDescriptor(descriptor);
            addSignature(signature, false);
            return new org.objectweb.asm.FieldVisitor(Opcodes.ASM9) {
                @Override
                public AnnotationVisitor visitAnnotation(String annotationDescriptor, boolean visible) {
                    referencedTypes.add(Type.getType(annotationDescriptor).getClassName());
                    return null;
                }
            };
        }

        private void addDescriptor(String descriptor) {
            if (descriptor == null || descriptor.isBlank()) return;
            try {
                Type type = descriptor.startsWith("(") ? Type.getMethodType(descriptor) : Type.getType(descriptor);
                addType(type);
            } catch (IllegalArgumentException ignored) {
                // Generic signatures are parsed separately where available.
            }
        }

        private void addType(Type type) {
            switch (type.getSort()) {
                case Type.ARRAY -> addType(type.getElementType());
                case Type.OBJECT -> referencedTypes.add(type.getClassName());
                case Type.METHOD -> {
                    for (Type argument : type.getArgumentTypes()) addType(argument);
                    addType(type.getReturnType());
                }
                default -> { }
            }
        }

        private void addInternalName(String name) {
            if (name != null && !name.isBlank()) referencedTypes.add(name.replace('/', '.'));
        }

        private void addSignature(String signature, boolean method) {
            if (signature == null) return;
            try {
                SignatureVisitor visitor = new SignatureVisitor(Opcodes.ASM9) {
                    private String current;

                    @Override
                    public void visitClassType(String name) {
                        current = name;
                        addInternalName(name);
                    }

                    @Override
                    public void visitInnerClassType(String name) {
                        current = current + "$" + name;
                        addInternalName(current);
                    }
                };
                SignatureReader reader = new SignatureReader(signature);
                if (method) reader.accept(visitor); else reader.acceptType(visitor);
            } catch (IllegalArgumentException ignored) {
                // Malformed signatures should not prevent indexing bytecode metadata.
            }
        }

        private static boolean isSpringMapping(String name) {
            return name.equals("RequestMapping") || name.equals("GetMapping") || name.equals("PostMapping")
                    || name.equals("PutMapping") || name.equals("DeleteMapping") || name.equals("PatchMapping");
        }

        private static List<String> mappingPaths(Map<String, List<String>> values) {
            List<String> paths = values.getOrDefault("path", values.getOrDefault("value", List.of()));
            return paths.stream().filter(value -> !value.isBlank()).toList();
        }

        private static List<String> springHttpMethods(String annotationName, Map<String, List<String>> values) {
            String fixed = switch (annotationName) {
                case "GetMapping" -> "GET";
                case "PostMapping" -> "POST";
                case "PutMapping" -> "PUT";
                case "DeleteMapping" -> "DELETE";
                case "PatchMapping" -> "PATCH";
                default -> null;
            };
            if (fixed != null) return List.of(fixed);
            List<String> methods = values.getOrDefault("method", List.of()).stream()
                    .map(value -> value.substring(value.lastIndexOf('.') + 1)).toList();
            return methods.isEmpty() ? List.of("ANY") : methods;
        }

        private static String joinRoute(String base, String path) {
            String left = base == null ? "" : base.trim();
            String right = path == null ? "" : path.trim();
            if (left.isEmpty() && right.isEmpty()) return "/";
            if (left.isEmpty()) left = "/";
            if (right.isEmpty()) return left.startsWith("/") ? left : "/" + left;
            String joined = (left.endsWith("/") ? left.substring(0, left.length() - 1) : left)
                    + "/" + (right.startsWith("/") ? right.substring(1) : right);
            joined = joined.replaceAll("/{2,}", "/");
            if (!joined.startsWith("/")) joined = "/" + joined;
            return joined.isEmpty() ? "/" : joined;
        }
    }

    private static final class AnnotationValues extends AnnotationVisitor {
        private final Map<String, List<String>> values = new java.util.LinkedHashMap<>();
        private final java.util.function.Consumer<Map<String, List<String>>> callback;

        AnnotationValues(java.util.function.Consumer<Map<String, List<String>>> callback) {
            super(Opcodes.ASM9);
            this.callback = callback;
        }

        @Override
        public void visit(String name, Object value) {
            if (value instanceof String text) {
                values.computeIfAbsent(name, ignored -> new ArrayList<>()).add(text);
            }
        }

        @Override
        public void visitEnum(String name, String descriptor, String value) {
            values.computeIfAbsent(name, ignored -> new ArrayList<>()).add(value);
        }

        @Override
        public AnnotationVisitor visitArray(String name) {
            List<String> items = values.computeIfAbsent(name, ignored -> new ArrayList<>());
            return new AnnotationVisitor(Opcodes.ASM9) {
                @Override
                public void visit(String ignored, Object value) {
                    if (value instanceof String text) items.add(text);
                }

                @Override
                public void visitEnum(String ignored, String descriptor, String value) {
                    items.add(value);
                }
            };
        }

        @Override
        public void visitEnd() {
            callback.accept(values);
        }
    }
}
