#define _GNU_SOURCE

#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>

#include <sched.h>

#include <sys/mount.h>
#include <sys/wait.h>

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

    FILE *fp;
    char * line = NULL;
    size_t len = 0;
    ssize_t read;
    int should_unshare = 0;
    fp = fopen("/etc/unshare-users", "r");
    if (fp == NULL) {
        _pam_log(LOG_WARNING, "pam_unshare pam_sm_open_session: %s: unable to open /etc/unshare-users", username);
	return PAM_SUCCESS;
    }
    while ((read = getline(&line, &len, fp)) != -1) {
        line[strcspn(line, "\r\n")] = 0;
        if (strcmp(line, username) == 0) {
            should_unshare = 1;
            break;
        }
    }

    fclose(fp);
    if (line) {
        free(line);
    }

    if (should_unshare == 0) {
        _pam_log(LOG_DEBUG, "pam_unshare pam_sm_open_session: %s: no need to unshare", username);
        return PAM_SUCCESS;
    }

    _pam_log(LOG_DEBUG, "pam_unshare pam_sm_open_session: %s: about to unshare", username);
    int unshare_err = unshare(CLONE_NEWPID | CLONE_NEWNS);
    if (unshare_err) {
        _pam_log(LOG_ERR, "pam_unshare pam_sm_open_session: %s: error unsharing: %s", username, strerror(errno));
        return PAM_SESSION_ERR;
    }
    _pam_log(LOG_DEBUG, "pam_unshare pam_sm_open_session: %s: successfully unshared", username);

    _pam_log(LOG_DEBUG, "pam_unshare pam_sm_open_session: %s: about to kick off a subprocess", username);
    int pid = fork();
    if (pid) {
        waitpid(pid, NULL, 0);
        exit(0);
    }

    _pam_log(LOG_DEBUG, "pam_unshare pam_sm_open_session: %s: in subprocess, about to mount /proc", username);
    mount("none", "/proc", NULL, MS_PRIVATE, NULL);
    mount("proc", "/proc", "proc", MS_NOSUID|MS_NOEXEC|MS_NODEV, NULL);
    signal(SIGCHLD, SIG_IGN);

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

