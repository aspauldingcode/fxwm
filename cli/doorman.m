/*
 * doorman.m - the Doorman command-line tool.
 *
 * A single binary that exposes the framework from the shell, and doubles as a
 * set of Linux-compatible account tools. When invoked under its own name it
 * takes subcommands:
 *
 *   doorman authenticate <user>        verify a password (reads it from stdin)
 *   doorman login <user> [--exec CMD]  authenticate then open/launch a session
 *   doorman useradd [opts] <name>      create a user
 *   doorman userdel [-r] <name>        delete a user
 *   doorman passwd [--stdin] <user>    set/reset a password
 *   doorman groupadd [-g gid] <name>   create a group
 *   doorman groupdel <name>            delete a group
 *   doorman usermod -aG <grp> <user>   add a user to a group
 *   doorman gpasswd -a|-d <user> <grp> add/remove a group member
 *   doorman users | sessions | groups <user>
 *
 * When the binary is invoked as `useradd`, `userdel`, `passwd`, `groupadd`,
 * `groupdel`, `usermod`, or `gpasswd` (via the symlinks the Makefile installs), it
 * behaves as that tool directly, so Linux account-management scripts and
 * habits work on macOS backed by this framework. The stock macOS/Unix tools
 * (`passwd`, `id`, `dscl`, ...) keep working too, since Doorman writes to the
 * same Open Directory store they read.
 */

#import <Foundation/Foundation.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <sys/wait.h>
#include <libgen.h>
#include <errno.h>
#include <limits.h>
#include "doorman.h"

/* --------------------------------------------------------------------- */
/* input helpers                                                         */
/* --------------------------------------------------------------------- */

/* Overwrite through a volatile pointer so the wipe is not optimised away,
 * then free. Used for plaintext passwords the CLI briefly holds. */
static void scrub_free(char *s) {
    if (!s) return;
    volatile unsigned char *p = (volatile unsigned char *)s;
    size_t len = strlen(s);
    while (len--) *p++ = 0;
    free(s);
}

static char *read_line_raw(const char *prompt) {
    if (prompt) { fputs(prompt, stderr); fflush(stderr); }
    char *line = NULL; size_t cap = 0;
    ssize_t n = getline(&line, &cap, stdin);
    if (n <= 0) { free(line); return NULL; }
    if (line[n - 1] == '\n') line[n - 1] = '\0';
    return line;
}

static char *read_secret(const char *prompt) {
    if (prompt) { fputs(prompt, stderr); fflush(stderr); }
    struct termios oldt, newt;
    bool isTty = (tcgetattr(STDIN_FILENO, &oldt) == 0);
    if (isTty) { newt = oldt; newt.c_lflag &= ~(tcflag_t)ECHO; tcsetattr(STDIN_FILENO, TCSANOW, &newt); }
    char *line = NULL; size_t cap = 0;
    ssize_t n = getline(&line, &cap, stdin);
    if (isTty) { tcsetattr(STDIN_FILENO, TCSANOW, &oldt); fputc('\n', stdout); }
    if (n <= 0) { free(line); return NULL; }
    if (line[n - 1] == '\n') line[n - 1] = '\0';
    return line;
}

/* Parse an unsigned decimal id (uid/gid) with full error checking; returns
 * false for empty, non-numeric, or out-of-range input rather than silently
 * coercing like atoi() would. */
static bool parse_id(const char *s, unsigned int *out) {
    if (!s || !*s) return false;
    errno = 0;
    char *end = NULL;
    unsigned long v = strtoul(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0' || v > UINT_MAX) return false;
    *out = (unsigned int)v;
    return true;
}

static doorman_backend_t parse_backend(const char *s) {
    if (!s) return DOORMAN_BACKEND_AUTO;
    if (strcmp(s, "opendirectory") == 0) return DOORMAN_BACKEND_OPENDIRECTORY;
    if (strcmp(s, "dslocal") == 0) return DOORMAN_BACKEND_DSLOCAL;
    if (strcmp(s, "pam") == 0) return DOORMAN_BACKEND_PAM;
    return DOORMAN_BACKEND_AUTO;
}

/* --------------------------------------------------------------------- */
/* conversation: serves password prompts from stdin                     */
/* --------------------------------------------------------------------- */

static int cli_conv(int num_msg, const doorman_message_t **msg,
                    doorman_response_t **resp, void *appdata) {
    (void)appdata;
    for (int i = 0; i < num_msg; i++) {
        switch (msg[i]->style) {
            case DOORMAN_PROMPT_ECHO_OFF:
                resp[i]->resp = read_secret(msg[i]->msg);
                if (!resp[i]->resp) return 1;
                break;
            case DOORMAN_PROMPT_ECHO_ON:
                resp[i]->resp = read_line_raw(msg[i]->msg);
                if (!resp[i]->resp) return 1;
                break;
            case DOORMAN_ERROR_MSG: fprintf(stderr, "%s\n", msg[i]->msg); break;
            case DOORMAN_TEXT_INFO: printf("%s\n", msg[i]->msg); break;
        }
    }
    return 0;
}

/* --------------------------------------------------------------------- */
/* subcommands                                                           */
/* --------------------------------------------------------------------- */

static int cmd_authenticate(int argc, char **argv) {
    const char *user = NULL, *backend = NULL;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--backend") == 0 && i + 1 < argc) backend = argv[++i];
        else if (argv[i][0] != '-') user = argv[i];
    }
    if (!user) { fprintf(stderr, "usage: doorman authenticate <user> [--backend b]\n"); return 2; }

    doorman_conv_t conv = { cli_conv, NULL };
    doorman_handle_t *h = NULL;
    if (doorman_start("login", user, &conv, parse_backend(backend), &h) != DOORMAN_SUCCESS) {
        fprintf(stderr, "doorman: could not start transaction\n"); return 1;
    }
    doorman_result_t r = doorman_authenticate(h);
    if (r == DOORMAN_SUCCESS) r = doorman_acct_mgmt(h);
    doorman_end(h);
    if (r == DOORMAN_SUCCESS) { printf("authentication succeeded for %s\n", user); return 0; }
    fprintf(stderr, "authentication failed for %s: %s\n", user, doorman_strerror(r));
    return 1;
}

static int cmd_login(int argc, char **argv) {
    const char *user = NULL, *backend = NULL, *sessionId = NULL;
    char *execCmd = NULL;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--backend") == 0 && i + 1 < argc) backend = argv[++i];
        else if (strcmp(argv[i], "--exec") == 0 && i + 1 < argc) execCmd = argv[++i];
        else if (strcmp(argv[i], "--session") == 0 && i + 1 < argc) sessionId = argv[++i];
        else if (argv[i][0] != '-') user = argv[i];
    }
    if (!user) { fprintf(stderr, "usage: doorman login <user> [--exec CMD] [--session ID]\n"); return 2; }

    doorman_conv_t conv = { cli_conv, NULL };
    doorman_handle_t *h = NULL;
    if (doorman_start("login", user, &conv, parse_backend(backend), &h) != DOORMAN_SUCCESS) return 1;

    doorman_result_t r = doorman_authenticate(h);
    if (r == DOORMAN_SUCCESS) r = doorman_acct_mgmt(h);
    if (r == DOORMAN_SUCCESS) r = doorman_setcred(h, DOORMAN_CRED_ESTABLISH);
    if (r != DOORMAN_SUCCESS) {
        fprintf(stderr, "login failed for %s: %s\n", user, doorman_strerror(r));
        doorman_end(h); return 1;
    }

    /* Choose a session: an explicit --exec wins; else a named/first session. */
    doorman_session_t adhoc = {0};
    doorman_session_t *chosen = NULL;
    doorman_session_t *sessions = NULL; size_t ns = 0;
    if (execCmd) {
        adhoc.id = "cli"; adhoc.name = "cli"; adhoc.exec = execCmd; adhoc.type = "tty";
        chosen = &adhoc;
    } else {
        doorman_enumerate_sessions(&sessions, &ns);
        for (size_t i = 0; i < ns; i++) {
            if (sessionId && strcmp(sessions[i].id, sessionId) == 0) { chosen = &sessions[i]; break; }
            if (!sessionId && !chosen) chosen = &sessions[i];
        }
    }
    if (!chosen) { fprintf(stderr, "no session to launch\n"); doorman_end(h); return 1; }

    pid_t pid = 0;
    r = doorman_open_session(h, chosen, &pid);
    int rc = 1;
    if (r == DOORMAN_SUCCESS) {
        int status = 0;
        waitpid(pid, &status, 0);
        rc = WIFEXITED(status) ? WEXITSTATUS(status) : 1;
        doorman_close_session(h);
    } else {
        fprintf(stderr, "could not open session: %s\n", doorman_strerror(r));
    }
    if (sessions) doorman_free_sessions(sessions, ns);
    doorman_end(h);
    return rc;
}

static int cmd_useradd(int argc, char **argv) {
    doorman_user_spec_t spec = {0};
    spec.create_home = true; /* macOS accounts want a home; use -M to skip */
    const char *addGroups = NULL;
    for (int i = 0; i < argc; i++) {
        const char *a = argv[i];
        if ((strcmp(a, "-m") == 0) || strcmp(a, "--create-home") == 0) spec.create_home = true;
        else if (strcmp(a, "-M") == 0 || strcmp(a, "--no-create-home") == 0) spec.create_home = false;
        else if ((strcmp(a, "-u") == 0 || strcmp(a, "--uid") == 0) && i + 1 < argc) { unsigned int v; if (parse_id(argv[++i], &v)) spec.uid = (uid_t)v; }
        else if ((strcmp(a, "-g") == 0 || strcmp(a, "--gid") == 0) && i + 1 < argc) { unsigned int v; if (parse_id(argv[++i], &v)) spec.gid = (gid_t)v; }
        else if ((strcmp(a, "-s") == 0 || strcmp(a, "--shell") == 0) && i + 1 < argc) spec.shell = argv[++i];
        else if ((strcmp(a, "-c") == 0 || strcmp(a, "--comment") == 0) && i + 1 < argc) spec.full_name = argv[++i];
        else if ((strcmp(a, "-d") == 0 || strcmp(a, "--home-dir") == 0) && i + 1 < argc) spec.home = argv[++i];
        else if ((strcmp(a, "-p") == 0 || strcmp(a, "--password") == 0) && i + 1 < argc) spec.password = argv[++i];
        else if ((strcmp(a, "-G") == 0 || strcmp(a, "--groups") == 0) && i + 1 < argc) addGroups = argv[++i];
        else if (strcmp(a, "--admin") == 0) spec.admin = true;
        else if (strcmp(a, "--hidden") == 0) spec.hidden = true;
        else if (a[0] != '-') spec.name = a;
    }
    if (!spec.name) { fprintf(stderr, "usage: doorman useradd [opts] <name>\n"); return 2; }

    doorman_result_t r = doorman_create_user(&spec);
    if (r != DOORMAN_SUCCESS) { fprintf(stderr, "useradd: %s\n", doorman_strerror(r)); return 1; }

    if (addGroups) {
        @autoreleasepool {
            NSString *g = [NSString stringWithUTF8String:addGroups];
            for (NSString *grp in [g componentsSeparatedByString:@","]) {
                if (grp.length) doorman_add_user_to_group(spec.name, grp.UTF8String);
            }
        }
    }
    printf("created user %s\n", spec.name);
    return 0;
}

static int cmd_userdel(int argc, char **argv) {
    const char *name = NULL; bool removeHome = false;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "-r") == 0 || strcmp(argv[i], "--remove") == 0) removeHome = true;
        else if (argv[i][0] != '-') name = argv[i];
    }
    if (!name) { fprintf(stderr, "usage: doorman userdel [-r] <name>\n"); return 2; }
    doorman_result_t r = doorman_delete_user(name, removeHome);
    if (r != DOORMAN_SUCCESS) { fprintf(stderr, "userdel: %s\n", doorman_strerror(r)); return 1; }
    printf("deleted user %s\n", name);
    return 0;
}

static int cmd_passwd(int argc, char **argv) {
    const char *user = NULL; bool useStdin = false;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--stdin") == 0) useStdin = true;
        else if (argv[i][0] != '-') user = argv[i];
    }
    if (!user) { fprintf(stderr, "usage: doorman passwd [--stdin] <user>\n"); return 2; }

    char *pw = NULL;
    if (useStdin || !isatty(STDIN_FILENO)) {
        pw = read_line_raw(NULL);
    } else {
        pw = read_secret("New password: ");
        char *confirm = read_secret("Retype new password: ");
        if (!pw || !confirm || strcmp(pw, confirm) != 0) {
            fprintf(stderr, "passwd: passwords do not match\n");
            scrub_free(pw); scrub_free(confirm); return 1;
        }
        scrub_free(confirm);
    }
    if (!pw) { fprintf(stderr, "passwd: no password provided\n"); return 1; }

    doorman_result_t r = doorman_set_password(user, pw);
    scrub_free(pw);
    if (r != DOORMAN_SUCCESS) { fprintf(stderr, "passwd: %s\n", doorman_strerror(r)); return 1; }
    printf("password updated for %s\n", user);
    return 0;
}

static int cmd_groupadd(int argc, char **argv) {
    const char *name = NULL, *real = NULL; gid_t gid = 0;
    for (int i = 0; i < argc; i++) {
        if ((strcmp(argv[i], "-g") == 0 || strcmp(argv[i], "--gid") == 0) && i + 1 < argc) { unsigned int v; if (parse_id(argv[++i], &v)) gid = (gid_t)v; }
        else if ((strcmp(argv[i], "-r") == 0 || strcmp(argv[i], "--realname") == 0) && i + 1 < argc) real = argv[++i];
        else if (argv[i][0] != '-') name = argv[i];
    }
    if (!name) { fprintf(stderr, "usage: doorman groupadd [-g gid] <name>\n"); return 2; }
    doorman_result_t r = doorman_create_group(name, gid, real);
    if (r != DOORMAN_SUCCESS) { fprintf(stderr, "groupadd: %s\n", doorman_strerror(r)); return 1; }
    printf("created group %s\n", name);
    return 0;
}

static int cmd_groupdel(int argc, char **argv) {
    const char *name = (argc > 0 && argv[argc - 1][0] != '-') ? argv[argc - 1] : NULL;
    if (!name) { fprintf(stderr, "usage: doorman groupdel <name>\n"); return 2; }
    doorman_result_t r = doorman_delete_group(name);
    if (r != DOORMAN_SUCCESS) { fprintf(stderr, "groupdel: %s\n", doorman_strerror(r)); return 1; }
    printf("deleted group %s\n", name);
    return 0;
}

static int cmd_gpasswd(int argc, char **argv) {
    /* gpasswd -a <user> <group>  (add), gpasswd -d <user> <group>  (remove) */
    const char *user = NULL, *group = NULL;
    int mode = 0; /* +1 add, -1 remove */
    for (int i = 0; i < argc; i++) {
        const char *a = argv[i];
        if ((strcmp(a, "-a") == 0 || strcmp(a, "--add") == 0) && i + 1 < argc) { user = argv[++i]; mode = 1; }
        else if ((strcmp(a, "-d") == 0 || strcmp(a, "--delete") == 0) && i + 1 < argc) { user = argv[++i]; mode = -1; }
        else if (a[0] != '-') group = a;
    }
    if (!user || !group || mode == 0) {
        fprintf(stderr, "usage: doorman gpasswd -a|-d <user> <group>\n"); return 2;
    }
    doorman_result_t r = (mode > 0) ? doorman_add_user_to_group(user, group)
                                    : doorman_remove_user_from_group(user, group);
    if (r != DOORMAN_SUCCESS) { fprintf(stderr, "gpasswd: %s\n", doorman_strerror(r)); return 1; }
    printf("%s %s %s group %s\n", mode > 0 ? "added" : "removed", user,
           mode > 0 ? "to" : "from", group);
    return 0;
}

static int cmd_usermod(int argc, char **argv) {
    /* Supports the common `usermod -aG <group> <user>` idiom. */
    const char *group = NULL, *user = NULL;
    for (int i = 0; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "-aG") == 0 || strcmp(a, "-Ga") == 0) { if (i + 1 < argc) group = argv[++i]; }
        else if (strcmp(a, "-G") == 0 || strcmp(a, "--groups") == 0) { if (i + 1 < argc) group = argv[++i]; }
        else if (strcmp(a, "-a") == 0 || strcmp(a, "--append") == 0) { /* flag */ }
        else if (a[0] != '-') user = a;
    }
    if (!group || !user) { fprintf(stderr, "usage: doorman usermod -aG <group> <user>\n"); return 2; }
    doorman_result_t r = doorman_add_user_to_group(user, group);
    if (r != DOORMAN_SUCCESS) { fprintf(stderr, "usermod: %s\n", doorman_strerror(r)); return 1; }
    printf("added %s to group %s\n", user, group);
    return 0;
}

static int cmd_users(void) {
    doorman_user_t *users = NULL; size_t n = 0;
    if (doorman_enumerate_users(true, &users, &n) != DOORMAN_SUCCESS) return 1;
    for (size_t i = 0; i < n; i++)
        printf("%-20s uid=%-6u %s\n", users[i].name, (unsigned)users[i].uid,
               users[i].full_name ? users[i].full_name : "");
    doorman_free_users(users, n);
    return 0;
}

static int cmd_sessions(void) {
    doorman_session_t *s = NULL; size_t n = 0;
    if (doorman_enumerate_sessions(&s, &n) != DOORMAN_SUCCESS) return 1;
    for (size_t i = 0; i < n; i++)
        printf("%-16s [%s] %s\n", s[i].id, s[i].type, s[i].exec);
    doorman_free_sessions(s, n);
    return 0;
}

static int cmd_groups(int argc, char **argv) {
    const char *user = (argc > 0 && argv[argc - 1][0] != '-') ? argv[argc - 1] : NULL;
    if (!user) { fprintf(stderr, "usage: doorman groups <user>\n"); return 2; }
    gid_t *g = NULL; size_t n = 0;
    if (doorman_get_groups(user, &g, &n) != DOORMAN_SUCCESS) { fprintf(stderr, "no such user\n"); return 1; }
    for (size_t i = 0; i < n; i++) printf("%u%s", (unsigned)g[i], i + 1 < n ? " " : "\n");
    free(g);
    return 0;
}

static int usage(void) {
    fprintf(stderr,
        "doorman - macOS authentication & account management (libdoorman)\n\n"
        "usage: doorman <command> [args]\n"
        "  authenticate <user>            verify a password (stdin)\n"
        "  login <user> [--exec CMD]      authenticate and open a session\n"
        "  useradd [opts] <name>          create a user (-m -u -g -s -c -d -p -G --admin)\n"
        "  userdel [-r] <name>            delete a user\n"
        "  passwd [--stdin] <user>        set/reset a password\n"
        "  groupadd [-g gid] <name>       create a group\n"
        "  groupdel <name>                delete a group\n"
        "  usermod -aG <group> <user>     add a user to a group\n"
        "  gpasswd -a|-d <user> <group>   add/remove a group member\n"
        "  users | sessions | groups <user>\n\n"
        "Also runs as useradd/userdel/passwd/groupadd/groupdel/usermod/gpasswd\n"
        "when invoked under those names.\n");
    return 2;
}

/* Dispatch a (command, argc, argv) triple. argv here starts at the first arg. */
static int dispatch(const char *cmd, int argc, char **argv) {
    if (strcmp(cmd, "authenticate") == 0) return cmd_authenticate(argc, argv);
    if (strcmp(cmd, "login") == 0)        return cmd_login(argc, argv);
    if (strcmp(cmd, "useradd") == 0)      return cmd_useradd(argc, argv);
    if (strcmp(cmd, "userdel") == 0)      return cmd_userdel(argc, argv);
    if (strcmp(cmd, "passwd") == 0)       return cmd_passwd(argc, argv);
    if (strcmp(cmd, "groupadd") == 0)     return cmd_groupadd(argc, argv);
    if (strcmp(cmd, "groupdel") == 0)     return cmd_groupdel(argc, argv);
    if (strcmp(cmd, "usermod") == 0)      return cmd_usermod(argc, argv);
    if (strcmp(cmd, "gpasswd") == 0)      return cmd_gpasswd(argc, argv);
    if (strcmp(cmd, "users") == 0)        return cmd_users();
    if (strcmp(cmd, "sessions") == 0)     return cmd_sessions();
    if (strcmp(cmd, "groups") == 0)       return cmd_groups(argc, argv);
    if (strcmp(cmd, "help") == 0 || strcmp(cmd, "--help") == 0 || strcmp(cmd, "-h") == 0) { usage(); return 0; }
    return usage();
}

int main(int argc, char **argv) {
    @autoreleasepool {
        char *base = basename(argv[0]);
        /* argv[0]-based Linux-tool compatibility. */
        static const char *tools[] = {"useradd","userdel","passwd","groupadd","groupdel","usermod","gpasswd",NULL};
        for (int i = 0; tools[i]; i++) {
            if (strcmp(base, tools[i]) == 0) {
                return dispatch(tools[i], argc - 1, argv + 1);
            }
        }
        if (argc < 2) return usage();
        return dispatch(argv[1], argc - 2, argv + 2);
    }
}
