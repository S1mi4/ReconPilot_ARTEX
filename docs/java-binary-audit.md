# Binary-only Java audit

ARTEX can audit Java source code reconstructed from uploaded JAR or CLASS files. Binary audits stay unavailable until the backend has a configured Vineflower JAR and Java 17 or newer.

## Configure

1. Obtain a trusted Vineflower command-line JAR from the [official project](https://github.com/Vineflower/vineflower).
2. Make that JAR available inside the backend container and set `ARTEX_VINEFLOWER_JAR` to its absolute path.
3. Ensure Java 17 or newer is available on `PATH`, or set `ARTEX_JAVA_BIN` to the Java executable.
4. Restart ARTEX and check the service audit configuration. Binary-only services become selectable for audit only after both settings are valid.

ARTEX does not download or update the decompiler automatically. Source-based audits do not require it. A configured JAR or CLASS-only service is decompiled only after a user manually starts an audit. Each decompilation uses a temporary directory, a one-gigabyte Java heap limit, and a five-minute timeout; temporary output is removed after the audit or review request.

The audit candidate records the uploaded artifact name and SHA-256, the decompiler JAR SHA-256, and the original class entry, package, class, and analyzed method for both the source and sink. A review re-decompiles the same immutable codebase version and rejects binary candidates whose provenance no longer matches. Existing evidence and independent review requirements still apply before Findings publication.

Vineflower's command-line and runtime requirements are documented in its [CLI usage](https://vineflower.org/usage/) and [project README](https://github.com/Vineflower/vineflower).
