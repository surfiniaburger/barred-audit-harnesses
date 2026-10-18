#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <signal.h>
#include <setjmp.h>

typedef uint32_t OM_uint32;
typedef void *gss_ctx_id_t;
typedef uint32_t gss_qop_t;
typedef struct { size_t length; void *value; } gss_buffer_desc, *gss_buffer_t;

#define GSS_C_NO_CONTEXT ((gss_ctx_id_t)0)
#define GSS_C_NO_BUFFER ((gss_buffer_t)0)
#define GSS_S_COMPLETE 0u
#define GSS_S_NO_CONTEXT 1u
#define GSS_S_BAD_MECH 2u
#define GSS_S_CALL_INACCESSIBLE_WRITE 3u
#define GSS_S_CALL_INACCESSIBLE_READ 4u
#define GSS_S_UNAVAILABLE 5u

typedef struct gss_OID_desc_struct { OM_uint32 length; void *elements; } gss_OID_desc, *gss_OID;

typedef struct gss_union_ctx_id_struct {
    struct gss_union_ctx_id_struct *loopback;
    gss_OID mech_type;
    gss_ctx_id_t internal_ctx_id;
} gss_union_ctx_id_desc, *gss_union_ctx_id_t;

typedef struct gss_mechanism_struct { int x; } *gss_mechanism;

/*
 * Faithful stub of the mechglue lookup.
 *
 * The audited implementation (Sun GSSAPI glue, 1998, g_process_context.c) calls
 * gssint_get_mechanism(ctx->mech_type) with NO validation of mech_type. The real
 * mechglue (MIT Kerberos / the Sun glue) dereferences mech_type to look up the
 * mechanism in its registry. The real mechglue is not available as a linkable
 * library in this environment (the 1998 Sun glue is the audited source, not a
 * shipped library), so this stub reproduces the dereference pattern: it reads
 * mech_type->length, which is exactly the first field access the real lookup
 * performs. The crash therefore demonstrates the mechanism in the reproduced
 * gss_get_mic call sequence, not a property of a separately linked library.
 */
static gss_mechanism gssint_get_mechanism(gss_OID mech_type) {
    if (mech_type == NULL) return NULL;
    volatile OM_uint32 l = mech_type->length;
    (void)l;
    return NULL;
}

static void map_error(OM_uint32 *m, gss_mechanism mech) { (void)m; (void)mech; }

static OM_uint32 val_get_mic_args(OM_uint32 *minor_status, gss_ctx_id_t context_handle,
    gss_qop_t qop_req, gss_buffer_t message_buffer, gss_buffer_t msg_token) {
    if (minor_status != NULL) *minor_status = 0;
    if (msg_token != GSS_C_NO_BUFFER) { msg_token->value = NULL; msg_token->length = 0; }
    if (minor_status == NULL) return GSS_S_CALL_INACCESSIBLE_WRITE;
    if (context_handle == GSS_C_NO_CONTEXT) return (GSS_S_CALL_INACCESSIBLE_READ | GSS_S_NO_CONTEXT);
    if (message_buffer == GSS_C_NO_BUFFER) return GSS_S_CALL_INACCESSIBLE_READ;
    if (msg_token == GSS_C_NO_BUFFER) return GSS_S_CALL_INACCESSIBLE_WRITE;
    return GSS_S_COMPLETE;
}

OM_uint32 gss_get_mic(OM_uint32 *minor_status, gss_ctx_id_t context_handle,
    gss_qop_t qop_req, gss_buffer_t message_buffer, gss_buffer_t msg_token) {
    OM_uint32 status;
    gss_union_ctx_id_t ctx;
    gss_mechanism mech;
    status = val_get_mic_args(minor_status, context_handle, qop_req, message_buffer, msg_token);
    if (status != GSS_S_COMPLETE) return status;
    ctx = (gss_union_ctx_id_t) context_handle;
    if (ctx->internal_ctx_id == GSS_C_NO_CONTEXT) return GSS_S_NO_CONTEXT;
    mech = gssint_get_mechanism(ctx->mech_type);
    if (mech) {
        return GSS_S_COMPLETE;
    }
    return GSS_S_BAD_MECH;
}

static jmp_buf jb;
static void handler(int sig) { longjmp(jb, sig); }

int main(void) {
    /* Case 1: crafted handle pointing to memory where internal_ctx_id != 0
       and mech_type points to unmapped memory. */
    gss_union_ctx_id_desc fake;
    fake.loopback = NULL;
    fake.internal_ctx_id = (gss_ctx_id_t)0x1; /* != GSS_C_NO_CONTEXT (0) */
    fake.mech_type = (gss_OID)0xdeadbeef;      /* garbage pointer */

    gss_buffer_desc msg = { 10, (void*)"hello" };
    gss_buffer_desc tok = { 0, NULL };
    OM_uint32 minor = 0;

    signal(SIGSEGV, handler);
    signal(SIGBUS, handler);
    if (setjmp(jb) != 0) {
        printf("RESULT: crash (SIGSEGV/SIGBUS) on crafted handle -> dereference reachable\n");
        return 0;
    }
    OM_uint32 r = gss_get_mic(&minor, (gss_ctx_id_t)&fake, 0, &msg, &tok);
    printf("RESULT: no crash, returned %u (minor=%u)\n", r, minor);
    return 0;
}
