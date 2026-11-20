package io.javacodedb;

import org.apache.lucene.document.Document;
import org.apache.lucene.document.Field;
import org.apache.lucene.document.StringField;
import org.apache.lucene.document.TextField;

import java.nio.charset.StandardCharsets;
import java.io.ByteArrayInputStream;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Set;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

final class ResourceIndexer {
    private static final Set<String> CONFIG_EXTENSIONS = Set.of(
            ".properties", ".yml", ".yaml", ".xml", ".json", ".conf", ".cfg", ".ini", ".toml", ".env");
    private static final Set<String> TEMPLATE_EXTENSIONS = Set.of(
            ".jsp", ".jspx", ".tag", ".tagx", ".ftl", ".vm", ".mustache", ".html");

    private ResourceIndexer() {
    }

    static String resourceKind(String path) {
        String lower = path.toLowerCase(Locale.ROOT);
        int slash = lower.lastIndexOf('/');
        String file = slash < 0 ? lower : lower.substring(slash + 1);
        int dot = file.lastIndexOf('.');
        String extension = dot < 0 ? "" : file.substring(dot);
        if (CONFIG_EXTENSIONS.contains(extension)) {
            return "config";
        }
        if (TEMPLATE_EXTENSIONS.contains(extension)
                && (!extension.equals(".html") || ("/" + lower + "/").contains("/templates/")
                    || ("/" + lower + "/").contains("/views/") || ("/" + lower + "/").contains("/web-inf/"))) {
            return "template";
        }
        return null;
    }

    static List<Document> toDocuments(ArtifactScanner.ResourceEntry entry) throws Exception {
        String content = new String(entry.bytes(), StandardCharsets.UTF_8);
        if (content.indexOf('\0') >= 0) {
            throw new IllegalArgumentException("Resource appears to be binary");
        }
        String hash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(entry.bytes()));
        Document document = new Document();
        addExact(document, "recordId", entry.id());
        addExact(document, "resourceId", entry.id());
        addExact(document, "docType", entry.kind());
        addExact(document, "artifact", entry.artifact());
        addExact(document, "entry", entry.entry());
        addExact(document, "application", Boolean.toString(!entry.entry().toLowerCase(Locale.ROOT)
                .matches(".*(?:boot-inf/lib|web-inf/lib|/lib|/libs)/.*")));
        addExact(document, "hash", hash);
        addExact(document, "pathExact", entry.entry());
        addText(document, "path", entry.entry());
        addText(document, "content", content);
        List<Document> documents = new ArrayList<>();
        documents.add(document);
        if (entry.entry().toLowerCase(Locale.ROOT).endsWith("web.xml")) {
            documents.addAll(webXmlEndpoints(entry));
        }
        return documents;
    }

    private static List<Document> webXmlEndpoints(ArtifactScanner.ResourceEntry entry) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        org.w3c.dom.Document xml = factory.newDocumentBuilder().parse(new ByteArrayInputStream(entry.bytes()));

        Map<String, String> servletClasses = new LinkedHashMap<>();
        NodeList servlets = xml.getElementsByTagNameNS("*", "servlet");
        for (int i = 0; i < servlets.getLength(); i++) {
            Element servlet = (Element) servlets.item(i);
            String name = childText(servlet, "servlet-name");
            String className = childText(servlet, "servlet-class");
            if (!name.isBlank()) servletClasses.put(name, className);
        }

        List<Document> documents = new ArrayList<>();
        NodeList mappings = xml.getElementsByTagNameNS("*", "servlet-mapping");
        for (int i = 0; i < mappings.getLength(); i++) {
            Element mapping = (Element) mappings.item(i);
            String servletName = childText(mapping, "servlet-name");
            String servletClass = servletClasses.getOrDefault(servletName, "");
            NodeList patterns = mapping.getElementsByTagNameNS("*", "url-pattern");
            for (int j = 0; j < patterns.getLength(); j++) {
                String route = patterns.item(j).getTextContent().trim();
                if (route.isBlank()) continue;
                org.apache.lucene.document.Document endpoint = new org.apache.lucene.document.Document();
                addExact(endpoint, "recordId", entry.id() + "#endpoint#" + servletName + "#" + route);
                addExact(endpoint, "resourceId", entry.id());
                addExact(endpoint, "docType", "endpoint");
                addExact(endpoint, "artifact", entry.artifact());
                addExact(endpoint, "entry", entry.entry());
                addExact(endpoint, "application", Boolean.toString(!entry.entry().toLowerCase(Locale.ROOT)
                        .matches(".*(?:boot-inf/lib|web-inf/lib|/lib|/libs)/.*")));
                addText(endpoint, "className", servletClass);
                addExact(endpoint, "endpointRouteExact", route);
                addText(endpoint, "endpointRoute", route);
                addExact(endpoint, "httpMethod", "ANY");
                addExact(endpoint, "endpointHandler", servletName);
                documents.add(endpoint);
            }
        }
        return documents;
    }

    private static String childText(Element parent, String name) {
        NodeList nodes = parent.getElementsByTagNameNS("*", name);
        if (nodes.getLength() == 0) return "";
        return nodes.item(0).getTextContent().trim();
    }

    private static void addExact(Document document, String field, String value) {
        document.add(new StringField(field, value, Field.Store.YES));
    }

    private static void addText(Document document, String field, String value) {
        document.add(new TextField(field, value, Field.Store.YES));
    }
}
