#include <stdio.h>
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

    SV *sv = newSVpv("AAAA", 4);
    STRLEN len;
    char *p = SvPV(sv, len);

    char buf[256];
    snprintf(buf, sizeof buf, "initial len=%lu pv=%p\n", (unsigned long)len, (void*)p);
    say(buf);

    STRLEN t_offset = 0;
    STRLEN s_offset = 0;
    STRLEN e_offset = 4;
    STRLEN grow = (STRLEN)-1 - e_offset - 1;
    snprintf(buf, sizeof buf, "grow=%lu (overflow value)\n", (unsigned long)grow);
    say(buf);

    say("calling SvGROW with huge size...\n");
    SvGROW(sv, e_offset + grow + 1);
    snprintf(buf, sizeof buf, "SvGROW returned; new len=%lu (NO CRASH - BAD)\n", (unsigned long)SvLEN(sv));
    say(buf);

    perl_destruct(my_perl);
    perl_free(my_perl);
    return 0;
}
