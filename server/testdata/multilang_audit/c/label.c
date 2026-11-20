#include <stddef.h>
#include <string.h>

/* Source-only audit fixture. src points to at least len readable bytes;
 * label points to a writable 16-byte destination. len is untrusted.
 * The two ranges do not overlap. No executable entry point or listener. */
void copy_unchecked(char label[16], const char *src, size_t len) {
    memcpy(label, src, len); /* C-COPY-WRITE: no destination bound check. */
    label[len] = '\0'; /* C-COPY-TERMINATOR: len == 16 also overflows. */
}

int copy_bounded(char label[16], const char *src, size_t len) {
    if (len >= 16) { /* C-COPY-CONTROL: reserve space for the terminator. */
        return 0;
    }
    memcpy(label, src, len);
    label[len] = '\0';
    return 1;
}
