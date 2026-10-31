/*
 * Minimal pcre.h for the security harnesses when libpcre is not
 * installed. The harnesses link a stub where every regex fails to match.
 */
#ifndef TESTS_SECURITY_STUB_PCRE_H
#define TESTS_SECURITY_STUB_PCRE_H
typedef struct real_pcre pcre;
typedef struct pcre_extra pcre_extra;
pcre *pcre_compile(const char *, int, const char **, int *,
    const unsigned char *);
int pcre_exec(const pcre *, const pcre_extra *, const char *, int, int,
    int, int *, int);
extern void (*pcre_free)(void *);
#endif
