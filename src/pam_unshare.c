#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define  PAM_SM_SESSION
#include <security/pam_modules.h>

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    printf("pam_unshare pam_sm_open_session\n");
    return PAM_SUCCESS;
}


PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    printf("pam_unshare pam_sm_close_session\n");
    return PAM_SUCCESS;
}
