/*
 * util.m - small, dependency-free helpers shared across the backends:
 * strict name validation and a constant-time byte comparison. Both are
 * security primitives, kept in one place so their behaviour is easy to audit.
 */

#include <stddef.h>
#include <stdbool.h>
#include "doorman_internal.h"

/* Longest short name we are willing to interpolate into a path or argv. */
#define DM_NAME_MAX 244

bool _dm_name_ok(const char *name) {
    if (!name) return false;

    size_t len = strnlen(name, DM_NAME_MAX + 1);
    if (len == 0 || len > DM_NAME_MAX) return false;

    /* A leading '-' could be mistaken for an option by a downstream tool; a
     * leading '.' invites "." / ".." path shenanigans in the dsLocal reader. */
    if (name[0] == '-' || name[0] == '.') return false;

    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)name[i];
        bool allowed = (c >= 'A' && c <= 'Z') ||
                       (c >= 'a' && c <= 'z') ||
                       (c >= '0' && c <= '9') ||
                       c == '_' || c == '-' || c == '.';
        if (!allowed) return false;
    }
    return true;
}

bool _dm_consttime_equal(const void *a, const void *b, size_t len) {
    if (!a || !b) return false;
    const volatile unsigned char *pa = (const volatile unsigned char *)a;
    const volatile unsigned char *pb = (const volatile unsigned char *)b;
    unsigned char accum = 0;
    for (size_t i = 0; i < len; i++)
        accum = (unsigned char)(accum | (unsigned char)(pa[i] ^ pb[i]));
    return accum == 0;
}
