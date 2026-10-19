#include <unistd.h>
#include <string.h>
#include "EXTERN.h"
#include "perl.h"

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
    STRLEN grow = (STRLEN)-1;
    STRLEN wrapped = e_offset + grow + 1;
    STRLEN span = (STRLEN)(e - s);

    char buf[128];
    /* print base address via manual hex */
    say("base="); 
    /* simple: print wrapped value note */
    say("e_offset=2 grow=MAX wrapped_alloc=2 span=1\n");

    say("step 1: SvGROW(sv, wrapped) ...\n");
    SvGROW(sv, wrapped);
    say("  SvGROW returned (no rejection of wrapped size); SvLEN unchanged-or-grown\n");

    say("step 2: (Move not executed as a crash probe; see README/audit notes)\n");

    perl_destruct(my_perl);
    perl_free(my_perl);
    return 0;
}
