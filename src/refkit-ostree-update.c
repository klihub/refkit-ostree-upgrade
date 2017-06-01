#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
#include <string.h>
#include <limits.h>
#include <locale.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#define _GNU_SOURCE                          /* getopt_long */
#include <getopt.h>

#include <ostree-1/ostree.h>


/* default hooks/scripts and updater interval */
#define UPDATER_HOOK(path) DATADIR"/refkit-ostree/hooks/"path
#define UPDATER_HOOK_APPLY UPDATER_HOOK("post-apply")
#define UPDATER_HOOK_BOOT  UPDATER_HOOK("reboot")
#define UPDATER_INTERVAL   (15 * 60)

/* updater modes */
enum {
    UPDATER_MODE_FETCH  = 0x1,               /* only fetch, don't apply */
    UPDATER_MODE_APPLY  = 0x2,               /* apply cached updates */
    UPDATER_MODE_UPDATE = 0x3,               /* fetch and apply updates */
};

/* updater runtime context */
typedef struct {
    int                    mode;             /* mode of operation */
    int                    interval;         /* update check interval */
    int                    oneshot;          /* run once, then exit */
    OstreeRepo            *repo;             /* ostree repo instance */
    OstreeSysroot         *sysroot;          /* ostree sysroot instance */
    OstreeSysrootUpgrader *u;                /* ostree sysroot upgrader */
    const char            *hook_apply;       /* post-update script */
    const char            *hook_boot;        /* request reboot script */
    int                    inhibit_fd;       /* shutdown inhibitor pid */
    int                    inhibit_pid;      /* active inhibitor process */
    const char            *argv0;            /* us... */
} context_t;

/* fd redirection for child process */
typedef struct {
    int parent;                              /* original file descriptor */
    int child;                               /* dupped to this one */
} redirfd_t;

/* log levels, current log level */
enum {
    UPDATER_LOG_NONE    = 0x00,
    UPDATER_LOG_FATAL   = 0x01,
    UPDATER_LOG_ERROR   = 0x02,
    UPDATER_LOG_WARN    = 0x04,
    UPDATER_LOG_INFO    = 0x08,
    UPDATER_LOG_DEBUG   = 0x10,
    UPDATER_LOG_ALL     = 0x1f,
    UPDATER_LOG_DAEMON  = UPDATER_LOG_WARN|UPDATER_LOG_ERROR|UPDATER_LOG_FATAL,
    UPDATER_LOG_CONSOLE = UPDATER_LOG_INFO|UPDATER_LOG_DAEMON,
};

static int log_mask;

/* logging macros */
#define log_fatal(...) log_msg(UPDATER_LOG_FATAL, __VA_ARGS__)
#define log_error(...) log_msg(UPDATER_LOG_ERROR, __VA_ARGS__)
#define log_warn(...)  log_msg(UPDATER_LOG_WARN , __VA_ARGS__)
#define log_info(...)  log_msg(UPDATER_LOG_INFO , __VA_ARGS__)
#define log_debug(...) log_msg(UPDATER_LOG_DEBUG, __VA_ARGS__)

/* macro to tag unused variables */
#define UNUSED_VAR(v) (void)v


static void log_msg(int lvl, const char *fmt, ...)
{
    static const char *prefix[] = {
        [UPDATER_LOG_FATAL] = "fatal error: ",
        [UPDATER_LOG_ERROR] = "error: ",
        [UPDATER_LOG_WARN]  = "warning: ",
        [UPDATER_LOG_INFO ] = "",
        [UPDATER_LOG_DEBUG] = "D: ",
    };
    FILE *out;
    va_list ap;

    if (!(log_mask & lvl) || lvl < UPDATER_LOG_NONE || lvl > UPDATER_LOG_DEBUG)
        return;

    switch (lvl) {
    case UPDATER_LOG_DEBUG:
    case UPDATER_LOG_INFO:
        out = stdout;
        break;
    default:
        out = stderr;
        break;
    }

    fputs(prefix[lvl], out);
    va_start(ap, fmt);
    vfprintf(out, fmt, ap);
    va_end(ap);
    fputc('\n', out);
    fflush(out);
}


static void log_handler(const gchar *domain, GLogLevelFlags level,
                        const gchar *message, gpointer user_data)
{
    static int map[] = {
        [G_LOG_LEVEL_CRITICAL]  = UPDATER_LOG_FATAL,
        [G_LOG_LEVEL_ERROR]     = UPDATER_LOG_ERROR,
        [G_LOG_LEVEL_WARNING]   = UPDATER_LOG_WARN,
        [G_LOG_LEVEL_MESSAGE]   = UPDATER_LOG_INFO,
        [G_LOG_LEVEL_INFO]      = UPDATER_LOG_INFO,
        [G_LOG_LEVEL_DEBUG]     = UPDATER_LOG_DEBUG,
    };
    int fatal, lvl;

    UNUSED_VAR(domain);
    UNUSED_VAR(user_data);

    fatal  = level & G_LOG_FLAG_FATAL;
    level &= G_LOG_LEVEL_MASK;

    if (level < 0 || level >= (int)(sizeof(map) / sizeof(map[0])))
        return;

    if (fatal)
        lvl = UPDATER_LOG_FATAL;
    else
        lvl = map[level];

    if (lvl == UPDATER_LOG_DEBUG)
        log_debug("[%s] %s", message);
    else
        log_msg(lvl, "%s", message);
}


static void set_defaults(context_t *c, const char *argv0)
{
    if (isatty(fileno(stdout)))
        log_mask = UPDATER_LOG_CONSOLE;
    else
        log_mask = UPDATER_LOG_DAEMON;

    memset(c, 0, sizeof(*c));
    c->mode       = UPDATER_MODE_UPDATE;
    c->interval   = UPDATER_INTERVAL;
    c->argv0      = argv0;
    c->hook_apply = UPDATER_HOOK_APPLY;
    c->hook_boot  = UPDATER_HOOK_BOOT;
}


static void print_usage(const char *argv0, int exit_code, const char *fmt, ...)
{
    va_list ap;

    if (fmt != NULL) {
        va_start(ap, fmt);
        vfprintf(stderr, fmt, ap);
        fputc('\n', stderr);
        va_end(ap);
    }

    fprintf(stderr, "usage: %s [options]\n"
            "\n"
            "The possible options are:\n"
            "  -F, --fetch-only             fetch without applying updates\n"
            "  -A, --apply-only             don't fetch, apply cached updates\n"
            "  -O, --one-shot               run once, then exit\n"
            "  -i, --check-interval         update check interval (in seconds)\n"
            "  -P, --post-apply-hook PATH   script to run after an update\n"
            "  -R, --reboot-hook PATH       script to request rebooting\n"
            "  -l, --log LEVELS             set logging levels\n"
            "  -v, --verbose                increase loggin verbosity\n"
            "  -d, --debug [DOMAINS]        enable given debug domains or all\n"
            "  -h, --help                   print this help on usage\n",
            argv0);

    exit(exit_code);
}


static int parse_log_levels(const char *levels)
{
    const char *l, *e, *n;
    int         c, mask;

    if (!strcmp(levels, "none"))
        return UPDATER_LOG_NONE;
    if (!strcmp(levels, "all"))
        return UPDATER_LOG_ALL;

    for (mask = 0, l = levels; l != NULL; l = n) {
        e = strchr(l, ',');
        if (e == NULL)
            n = NULL;
        else
            n = e + 1;

        if ((c = e - l) == 0)
            continue;

        switch (c) {
        case 4:
            if (!strncmp(l, "none", 4))
                continue;
            else if (!strncmp(l, "info", 4))
                mask |= UPDATER_LOG_INFO;
            else if (!strncmp(l, "warn", 4))
                mask |= UPDATER_LOG_WARN;
            else
                goto ignore_unknown;
            break;

        case 5:
            if (!strncmp(l, "debug", 5))
                mask |= UPDATER_LOG_DEBUG;
            else if (!strncmp(l, "error", 5))
                mask |= UPDATER_LOG_ERROR;
            else if (!strncmp(l, "fatal", 5))
                mask |= UPDATER_LOG_FATAL;
            else
                goto ignore_unknown;
            break;

        case 6:
            if (!strncmp(l, "daemon", 6))
                mask |= UPDATER_LOG_DAEMON;
            else
                goto ignore_unknown;
            break;

        case 7:
            if (!strncmp(l, "console", 7))
                mask |= UPDATER_LOG_CONSOLE;
            else
                goto ignore_unknown;
            break;

        default:
        ignore_unknown:
            log_error("unknown log level %*.*s", c, c, l);
            return log_mask;
        }
    }

    return mask;
}


static void enable_debug_domains(char **domains)
{
    static char   debug[1024];
    char        **dom, *p;
    const char   *t;
    int           l, n;

    p = debug;
    l = sizeof(debug);
    for (dom = domains, t = ""; *dom && l > 0; dom++, t = ",") {
        n = snprintf(p, l, "%s%s", t, *dom);

        if (n < 0 || n >= l) {
            *p = '\0';
            l  = 0;
        }
        else {
            p += n;
            l -= n;
        }
    }

    log_mask |= UPDATER_LOG_DEBUG;

    log_debug("enabling debug domains '%s'", debug);
    setenv("G_MESSAGES_DEBUG", debug, TRUE);
}


static void parse_cmdline(context_t *c, int argc, char **argv)
{
#   define OPTIONS "-FAOi:P:R:l:vd::h"
    static struct option options[] = {
        { "fetch-only"     , no_argument      , NULL, 'F' },
        { "apply-only"     , no_argument      , NULL, 'A' },
        { "one-shot"       , no_argument      , NULL, 'O' },
        { "check-interval" , required_argument, NULL, 'i' },
        { "post-apply-hook", required_argument, NULL, 'P' },
        { "reboot-hook"    , required_argument, NULL, 'R' },
        { "log"            , required_argument, NULL, 'l' },
        { "verbose"        , no_argument      , NULL, 'v' },
        { "debug"          , optional_argument, NULL, 'd' },
        { "help"           , no_argument      , NULL, 'h' },
        { NULL, 0, NULL, 0 }
    };
    static char *domains[32] = { [0 ... 31] = NULL };
    int          ndomain     = 0;

    int   opt, vmask, lmask;
    char *e;

    set_defaults(c, argv[0]);
    lmask = 0;
    vmask = log_mask;

    while ((opt = getopt_long(argc, argv, OPTIONS, options, NULL)) != -1) {
        switch (opt) {
        case 'F':
            c->mode = UPDATER_MODE_FETCH;
            break;

        case 'A':
            c->mode = UPDATER_MODE_APPLY;
            break;

        case 'O':
            c->oneshot = 1;
            break;

        case 'i':
            c->interval = strtol(optarg, &e, 10);
            if (e && *e)
                log_fatal("invalid update check interval '%s'", optarg);
            break;

        case 'P':
            c->hook_apply = optarg;
            break;

        case 'R':
            c->hook_boot = optarg;
            break;

        case 'l':
            lmask = parse_log_levels(optarg);
            break;

        case 'v':
            vmask <<= 1;
            vmask |= 1;
            break;

        case 'd':
            if (optarg == NULL || (optarg[0] == '*' && optarg[1] == '\0'))
                optarg = "all";

            if (ndomain < (int)(sizeof(domains) / sizeof(domains[0])) - 1)
                domains[ndomain++] = optarg;
            else
                log_warn("too many debug domains, ignoring '%s'...", optarg);
            break;

        case 'h':
            print_usage(argv[0], 0, "");

        case '?':
            print_usage(argv[0], EINVAL, "invalid option");
            break;
        }
    }
#undef OPTIONS

    if (vmask && lmask)
        log_warn("both -v and -l options used to change logging level...");

    log_mask = vmask | lmask | UPDATER_LOG_FATAL;

    if (ndomain > 0)
        enable_debug_domains(domains);
}


static void updater_init(context_t *c)
{
    GCancellable *gcnc = NULL;
    GError       *gerr = NULL;

    c->repo = ostree_repo_new_default();

    if (!ostree_repo_open(c->repo, gcnc, &gerr))
        log_fatal("failed to open OSTree repository (%s)", gerr->message);
}


static pid_t updater_invoke(char **argv, redirfd_t *rfd)
{
    pid_t      pid;
    redirfd_t *r;
    int        i, fd;

    switch ((pid = fork())) {
    case -1:
        log_error("failed to fork to exec '%s'", argv[0]);
        return -1;

    case 0:
        /*
         * child
         *   - close file descriptors skip the ones we will be dup2'ing
         *   - do filedescriptor redirections
         *   - exec
         */

        for (i = 0; i < sysconf(_SC_OPEN_MAX); i++) {
            fd = i;

            if (fd == fileno(stdout) && (log_mask & UPDATER_LOG_DEBUG))
                continue;

            if (rfd != NULL) {
                for (r = rfd; r->parent >= 0 && fd >= 0; r++)
                    if (r->parent == i)
                        fd = -1;
            }

            if (fd >= 0)
                close(fd);
        }

        if (rfd != NULL) {
            for (r = rfd; r->parent >= 0; r++) {
                if (rfd->parent == rfd->child)
                    continue;

                log_debug("redirecting child fd %d -> %d", r->child, r->parent);

                dup2(r->parent, r->child);
                close(r->parent);
            }
        }

        if (execv(argv[0], argv) < 0) {
            log_error("failed to exec '%s' (%d: %s)", argv[0],
                      errno, strerror(errno));
            exit(-1);
        }
        break;

    default:
        /*
         * parent
         *   - close file descriptor we'll be using on the child side
         */

        if (rfd != NULL) {
            for (r = rfd; r->parent >= 0; r++) {
                log_debug("closing parent fd %d", r->parent);
                close(r->parent);
            }
        }

        break;
    }

    return pid;
}


static int updater_block_shutdown(context_t *c)
{
#   define RD 0
#   define WR 1

    char      *argv[16], *path;
    int        argc, pipefds[2];
    redirfd_t  rfd[2];

    if (c->inhibit_pid > 0)
        return 0;

    if (access((path = "/usr/bin/systemd-inhibit"), X_OK) != 0)
        if (access((path = "/bin/systemd-inhibit"), X_OK) != 0)
            goto no_inhibit;

    log_debug("using %s to block system shutdown/reboot...", path);

    /*
     * systemd-inhibit --what=shutdown --who=ostree-updater \
     *    --why='pulling/applying system update' --mode=block \
     *    /bin/sh -c "read foo; exit 0"
     */

    argc = 0;
    argv[argc++] = path;
    argv[argc++] = "--what=shutdown";
    argv[argc++] = "--who=ostree-update";
    argv[argc++] = "--why=pulling/applying system update";
    argv[argc++] = "--mode=block";
    argv[argc++] = "/bin/sh";
    argv[argc++] = "-c";
    argv[argc++] = "read foo";
    argv[argc++] = NULL;

    if (pipe(pipefds) < 0)
        goto pipe_err;

    rfd[0].parent = pipefds[RD];
    rfd[0].child  = fileno(stdin);
    rfd[1].parent = rfd[1].child = -1;
    c->inhibit_fd = pipefds[WR];

    log_info("activating shutdown-inhibitor...");

    c->inhibit_pid = updater_invoke(argv, rfd);

    if (c->inhibit_pid < 0) {
        close(pipefds[WR]);
        c->inhibit_fd = -1;

        return -1;
    }

    return 0;

 no_inhibit:
    log_error("failed to find an executable systemd-inhibit");
    return -1;

 pipe_err:
    log_error("failed to create pipe for systemd-inhibit");
    return -1;

#undef RD
#undef WR
}


static void updater_allow_shutdown(context_t *c)
{
    pid_t pid;
    int   cnt, ec;

    if (!c->inhibit_pid && c->inhibit_fd < 0) {
        c->inhibit_pid = 0;
        c->inhibit_fd  = -1;

        return;
    }

    log_info("deactivating shutdown-inhibitor...");

    close(c->inhibit_fd);
    c->inhibit_fd = -1;

    usleep(10 * 1000);

    cnt = 0;
    while ((pid = waitpid(c->inhibit_pid, &ec, WNOHANG)) != c->inhibit_pid) {
        if (cnt++ < 5)
            usleep(250 * 1000);
        else
            break;
    }

    if (pid <= 0) {
        log_warn("Hmm... hammering inhibitor child (%u)...", c->inhibit_pid);
        kill(c->inhibit_pid, SIGKILL);
    }

    c->inhibit_pid = 0;
    c->inhibit_fd  = -1;
}


static int updater_prepare(context_t *c)
{
    GCancellable *gcnc   = NULL;
    GError       *gerr   = NULL;
    gboolean      locked = FALSE;

    if (c->sysroot == NULL)
        c->sysroot = ostree_sysroot_new(NULL);

    if (!ostree_sysroot_load(c->sysroot, gcnc, &gerr))
        goto load_failure;

    if (!ostree_sysroot_try_lock(c->sysroot, &locked, &gerr))
        goto lock_failure;

    if (!locked)
        return 0;

    if (updater_block_shutdown(c) < 0)
        goto block_failure;

    c->u = ostree_sysroot_upgrader_new_for_os(c->sysroot, NULL, gcnc, &gerr);

    if (c->u == NULL)
        goto no_upgrader;

    return 1;

 load_failure:
    log_error("failed to load OSTree sysroot (%s)", gerr->message);
    return -1;

 lock_failure:
    log_error("failed to lock OSTree sysroot (%s)", gerr->message);
    return -1;

 block_failure:
    log_error("failed to block shutdown");
    return -1;

 no_upgrader:
    log_error("failed to create OSTree upgrader (%s)", gerr->message);
    return -1;
}


static void updater_cleanup(context_t *c)
{
    if (c->sysroot)
        ostree_sysroot_unlock(c->sysroot);

    if (c->u) {
        g_object_unref(c->u);
        c->u = NULL;
    }

    updater_allow_shutdown(c);
}


static int updater_post_apply_hook(context_t *c, const char *o, const char *n)
{
#   define TIMEOUT 60

    char      *argv[8];
    int        argc, cnt;
    redirfd_t  rfd[3];
    pid_t      pid, ec, status;

    if (!*c->hook_apply)
        goto no_hook;

    if (access(c->hook_apply, X_OK) < 0)
        goto no_access;

    argc = 0;
    argv[argc++] = (char *)c->hook_apply;
    if (o != NULL && n != NULL) {
        argv[argc++] = (char *)o;
        argv[argc++] = (char *)n;
    }
    argv[argc] = NULL;

    rfd[0].parent = rfd[0].child = fileno(stdout);
    rfd[1].parent = rfd[1].child = fileno(stderr);
    rfd[2].parent = rfd[2].child = -1;

    pid = updater_invoke(argv, rfd);

    if (pid <= 0)
        return -1;

    log_info("waiting for post-apply hook (%s) to finish...", c->hook_apply);

    while ((status = waitpid(pid, &ec, WNOHANG)) != pid) {
        if (cnt++ < TIMEOUT)
            sleep(1);
        else
            break;
    }

    if (status != pid)
        goto timeout;

    if (!WIFEXITED(ec))
        goto hook_error;

    if (WEXITSTATUS(ec) != 0)
        goto hook_failure;

    log_info("post-apply hook (%s) succeeded", c->hook_apply);
    return 0;

 no_hook:
    return 0;

 no_access:
    log_error("can't execute post-apply hook '%s'", c->hook_apply);
    return -1;

 timeout:
    log_error("post-apply hook (%s) didn't finish in %d seconds",
              c->hook_apply, TIMEOUT);
    return -1;

 hook_error:
    log_error("post-apply hook (%s) exited abnormally", c->hook_apply);
    return -1;

 hook_failure:
    log_error("post-apply hook (%s) failed with status %d", c->hook_apply,
              WEXITSTATUS(ec));
    return -1;

#   undef TIMEOUT
}


static int updater_reboot_hook(context_t *c)
{
#   define TIMEOUT 60

    char *argv[8];
    pid_t pid;
    int   status, ec, cnt;

    if (!*c->hook_boot)
        goto no_hook;

    if (access(c->hook_boot, X_OK) < 0)
        goto no_access;

    log_info("running post-apply boot hook %s...", c->hook_boot);

    argv[0] = (char *)c->hook_boot;
    argv[1] = NULL;

    pid = updater_invoke(argv, NULL);

    if (pid < 0)
        return -1;

    log_info("waiting for boot hook (%s) to finish...", c->hook_boot);

    cnt = 0;
    while ((status = waitpid(pid, &ec, WNOHANG)) != pid) {
        if (cnt++ < TIMEOUT)
            sleep(1);
        else
            break;
    }

    if (status != pid)
        goto timeout;

    if (!WIFEXITED(ec))
        goto hook_error;

    if (WEXITSTATUS(ec) != 0)
        goto hook_failure;

    log_info("boot hook (%s) succeeded, exiting", c->hook_apply);
    exit(0);

 no_hook:
    return 0;

 no_access:
    log_error("can't execute post-apply boot hook '%s'", c->hook_boot);
    return -1;

 timeout:
    log_error("boot hook (%s) didn't finish in %d seconds",
              c->hook_boot, TIMEOUT);
    return -1;

 hook_error:
    log_error("boot hook (%s) exited abnormally", c->hook_boot);
    return -1;

 hook_failure:
    log_error("boot hook (%s) failed with status %d", c->hook_boot,
              WEXITSTATUS(ec));
    return -1;

#   undef TIMEOUT
}


static int updater_fetch(context_t *c)
{
    GCancellable *gcnc = NULL;
    GError       *gerr = NULL;
    int           flg  = 0;
    int           changed;
    const char   *src;

    if (!(c->mode & UPDATER_MODE_FETCH)) {
        flg = OSTREE_SYSROOT_UPGRADER_PULL_FLAGS_SYNTHETIC;
        src = "local repository";
    }
    else
        src = "server";

    log_info("polling OSTree %s for available updates...", src);

    if (!ostree_sysroot_upgrader_pull(c->u, 0, flg, NULL, &changed, gcnc, &gerr))
        goto pull_failed;

    if (!changed)
        log_info("no updates pending");
    else
        log_info("updates fetched successfully");

    return changed;

 pull_failed:
    log_error("failed to poll %s for updates (%s)", src, gerr->message);
    if (!(c->mode & UPDATER_MODE_APPLY))         /* mimick stock ostree logic */
        ostree_sysroot_cleanup(c->sysroot, NULL, NULL);
    return -1;
}


static int updater_apply(context_t *c)
{
    GCancellable *gcnc = NULL;
    GError       *gerr = NULL;

    if (!(c->mode & UPDATER_MODE_APPLY))
        return 0;

    if (!ostree_sysroot_upgrader_deploy(c->u, gcnc, &gerr))
        goto deploy_failure;

    log_info("OSTree updates applied");

    if (updater_post_apply_hook(c, NULL, NULL) < 0)
        goto hook_failure;

    return 1;

 deploy_failure:
    log_error("failed to deploy OSTree updates locally (%s)", gerr->message);
    return -1;

 hook_failure:
    log_error("update post-apply hook failed");
    return -1;
}


static int updater_run(context_t *c)
{
    int status;

    if (updater_prepare(c) <= 0)
        return -1;

    if ((status = updater_fetch(c)) > 0)
        status = updater_apply(c);

    updater_cleanup(c);

    return status;
}


static void updater_loop(context_t *c)
{
    int updated;

    /*
     * Notes:
     *
     *   This is extremely simplistic now. Since ostree uses heavily
     *   gobjects/GMmainLoop we could easily/perhaps should switch
     *   to using GMainLoop.
     */

    for (;;) {
        updated = updater_run(c);

        if (c->oneshot)
            break;

        switch (updated) {
        case 0:
            /* no updates, wait for next poll time */
            sleep(c->interval);
            break;

        case 1:
            updater_reboot_hook(c); /* does not return on success */
            exit(1);

        default:
            sleep(30);
            break;
        }
    }
}



static void updater_exit(context_t *c)
{
    UNUSED_VAR(c);
}


int main(int argc, char *argv[])
{
    context_t c;

    setlocale(LC_ALL, "");

    g_set_prgname(argv[0]);
    g_setenv("GIO_USE_VFS", "local", TRUE);
    g_log_set_handler(G_LOG_DOMAIN, G_LOG_LEVEL_MESSAGE, log_handler, NULL);

    parse_cmdline(&c, argc, argv);

    updater_init(&c);
    updater_loop(&c);
    updater_exit(&c);

    return 0;
}

