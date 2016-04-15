#define _GNU_SOURCE

#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>

#include <sched.h>

#include <sys/mount.h>

#define  PAM_SM_SESSION
#include <security/pam_modules.h>


static void _pam_log(int err, const char *format, ...) {
  va_list args;

  va_start(args, format);
  openlog("pam_unshare", LOG_PID, LOG_AUTHPRIV);
  vsyslog(err, format, args);
  va_end(args);
  closelog();
}


PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *username;
    if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS) {
        _pam_log(LOG_ERR, "pam_unshare pam_sm_open_session: could not get username");
        return PAM_SESSION_ERR;
    }
    _pam_log(LOG_DEBUG, "pam_unshare pam_sm_open_session: %s: start", username);

    _pam_log(LOG_DEBUG, "pam_unshare pam_sm_open_session: %s: about to unshare", username);
    int unshare_err = unshare(CLONE_NEWPID | CLONE_NEWNS);
    if (unshare_err) {
        _pam_log(LOG_ERR, "pam_unshare pam_sm_open_session: %s: error unsharing: %s", username, strerror(errno));
        return PAM_SESSION_ERR;
    }
    _pam_log(LOG_DEBUG, "pam_unshare pam_sm_open_session: %s: successfully unshared", username);

    if (access("/proc/cpuinfo", R_OK)) {
        _pam_log(LOG_DEBUG, "pam_unshare pam_sm_open_session: %s: no need to umount /proc", username);
    } else {
        _pam_log(LOG_DEBUG, "pam_unshare pam_sm_open_session: %s: about to umount /proc", username);
        int umount_err = umount("/proc");
        if (umount_err) {
            _pam_log(LOG_ERR, "pam_unshare pam_sm_open_session: %s: error umounting /proc: %s", username, strerror(errno));
            return PAM_SESSION_ERR;
        }
        _pam_log(LOG_DEBUG, "pam_unshare pam_sm_open_session: %s: successfully umounted /proc", username);
    }

    _pam_log(LOG_DEBUG, "pam_unshare pam_sm_open_session: %s: done", username);
    return PAM_SUCCESS;
}


PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *username;
    if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS) {
        _pam_log(LOG_ERR, "pam_unshare pam_sm_close_session: could not get username");
        return PAM_SESSION_ERR;
    }
    _pam_log(LOG_DEBUG, "pam_unshare pam_sm_close_session: %s: start", username);
    _pam_log(LOG_DEBUG, "pam_unshare pam_sm_close_session: %s: done", username);
    return PAM_SUCCESS;
}
