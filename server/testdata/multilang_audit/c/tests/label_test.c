#include <assert.h>
#include <stddef.h>
#include <string.h>

/* Context only: never compiled or executed by the Go inventory regression. */
int copy_bounded(char label[16], const char *src, size_t len);

void test_copy_bounded(void) {
    char label[16] = "unchanged";
    const char src[] = "0123456789abcdef";
    assert(copy_bounded(label, src, 16) == 0);
    assert(strcmp(label, "unchanged") == 0);
    assert(copy_bounded(label, src, 15) == 1);
    assert(label[15] == '\0');
}
