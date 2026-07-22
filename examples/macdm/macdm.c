/*
 * macdm.c - a tiny console "display manager" built on libdoorman.
 *
 * This is a worked example of how a login program (for instance a port of a
 * Wayland display manager to macOS) consumes the framework:
 *
 *   1. list interactive users        (doorman_enumerate_users)
 *   2. list available sessions       (doorman_enumerate_sessions)
 *   3. authenticate via a PAM-style conversation callback
 *      (doorman_start / doorman_authenticate / doorman_acct_mgmt)
 *   4. launch the chosen session      (doorman_open_session)
 *
 * It is deliberately UI-free (reads from the terminal) so it demonstrates the
 * library contract rather than any particular renderer. A graphical display
 * manager would consume the exact same API.
 *
 * Build (on macOS):
 *   cc macdm.c -I../../doorman/include -L<doorman>/lib -ldoorman \
 *      -framework Foundation -framework OpenDirectory -framework Security -lpam
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include "doorman.h"

/* Read a line with echo disabled, for passwords. Caller frees the result. */
static char *read_secret(const char *prompt) {
    fputs(prompt, stdout);
    fflush(stdout);

    struct termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(tcflag_t)ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    char *line = NULL;
    size_t cap = 0;
    ssize_t n = getline(&line, &cap, stdin);

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    fputc('\n', stdout);

    if (n <= 0) { free(line); return NULL; }
    if (line[n - 1] == '\n') line[n - 1] = '\0';
    return line;
}

/*
 * Conversation callback. The library calls this whenever it needs input; here
 * we service ECHO_OFF prompts (passwords) from the terminal and print info /
 * error messages. This is the same shape as a Linux PAM conversation function.
 */
static int conversation(int num_msg,
                        const doorman_message_t **msg,
                        doorman_response_t **resp,
                        void *appdata) {
    (void)appdata;
    for (int i = 0; i < num_msg; i++) {
        switch (msg[i]->style) {
            case DOORMAN_PROMPT_ECHO_OFF:
                resp[i]->resp = read_secret(msg[i]->msg);
                if (!resp[i]->resp) return 1;
                break;
            case DOORMAN_PROMPT_ECHO_ON: {
                fputs(msg[i]->msg, stdout);
                fflush(stdout);
                char *line = NULL; size_t cap = 0;
                ssize_t n = getline(&line, &cap, stdin);
                if (n <= 0) { free(line); return 1; }
                if (line[n - 1] == '\n') line[n - 1] = '\0';
                resp[i]->resp = line;
                break;
            }
            case DOORMAN_ERROR_MSG:
                fprintf(stderr, "%s\n", msg[i]->msg);
                break;
            case DOORMAN_TEXT_INFO:
                printf("%s\n", msg[i]->msg);
                break;
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    doorman_backend_t backend = DOORMAN_BACKEND_AUTO;
    if (argc > 1) {
        if (strcmp(argv[1], "pam") == 0) backend = DOORMAN_BACKEND_PAM;
        else if (strcmp(argv[1], "opendirectory") == 0) backend = DOORMAN_BACKEND_OPENDIRECTORY;
        else if (strcmp(argv[1], "dslocal") == 0) backend = DOORMAN_BACKEND_DSLOCAL;
    }

    printf("=== macdm (libdoorman demo) ===\n\n");

    /* 1. Users. */
    doorman_user_t *users = NULL; size_t nusers = 0;
    if (doorman_enumerate_users(true, &users, &nusers) == DOORMAN_SUCCESS) {
        printf("Users:\n");
        for (size_t i = 0; i < nusers; i++)
            printf("  - %s (%s, uid=%u)\n", users[i].name,
                   users[i].full_name ? users[i].full_name : "", (unsigned)users[i].uid);
        doorman_free_users(users, nusers);
    }

    /* 2. Sessions. */
    doorman_session_t *sessions = NULL; size_t nsessions = 0;
    doorman_enumerate_sessions(&sessions, &nsessions);
    printf("\nSessions:\n");
    for (size_t i = 0; i < nsessions; i++)
        printf("  [%zu] %s (%s) -> %s\n", i, sessions[i].name, sessions[i].type, sessions[i].exec);

    /* 3. Authenticate. */
    printf("\nUsername: ");
    fflush(stdout);
    char *user = NULL; size_t cap = 0;
    ssize_t n = getline(&user, &cap, stdin);
    if (n <= 0) { free(user); return 1; }
    if (user[n - 1] == '\n') user[n - 1] = '\0';

    doorman_conv_t conv = { .conv = conversation, .appdata = NULL };
    doorman_handle_t *h = NULL;
    if (doorman_start("login", user, &conv, backend, &h) != DOORMAN_SUCCESS) {
        fprintf(stderr, "could not start auth transaction\n");
        free(user);
        return 1;
    }

    doorman_result_t r = doorman_authenticate(h);
    if (r == DOORMAN_SUCCESS) r = doorman_acct_mgmt(h);
    if (r == DOORMAN_SUCCESS) r = doorman_setcred(h, DOORMAN_CRED_ESTABLISH);

    if (r != DOORMAN_SUCCESS) {
        fprintf(stderr, "login failed: %s\n", doorman_strerror(r));
        doorman_end(h);
        doorman_free_sessions(sessions, nsessions);
        free(user);
        return 1;
    }
    printf("Authentication succeeded for %s.\n", user);

    /* Supplementary groups, the way a login program resolves them before
     * dropping privileges (getgrouplist parity). */
    gid_t *gids = NULL; size_t ngids = 0;
    if (doorman_get_groups(user, &gids, &ngids) == DOORMAN_SUCCESS) {
        printf("Groups (%zu):", ngids);
        for (size_t i = 0; i < ngids; i++) printf(" %u", (unsigned)gids[i]);
        printf("\n");
        free(gids);
    }

    /* 4. Launch a session (only if there is a real one and we can). */
    if (nsessions > 0) {
        pid_t pid = 0;
        r = doorman_open_session(h, &sessions[0], &pid);
        if (r == DOORMAN_SUCCESS)
            printf("Launched session '%s' as pid %d.\n", sessions[0].name, (int)pid);
        else
            printf("Session not launched: %s\n", doorman_strerror(r));
    }

    doorman_end(h);
    doorman_free_sessions(sessions, nsessions);
    free(user);
    return 0;
}
