/*************************************************************************
    > File Name: chIdentity.c
    > Author: soh0ro0t
    > Mail: thebeemangg@gmail.com 
    > Created Time: 2042年03月21日 星期日 00时31分34秒
 ************************************************************************/
#define PROGNAME  "chIdentity"
#define LOG_TAG   PROGNAME
#define _GNU_SOURCE         /* See feature_test_macros(7) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <stdarg.h>
#include <error.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/xattr.h>
#include <getopt.h>
#include <grp.h>

#define AID_APP_START 10000 /* first app user */
#define AID_APP_END 19999   /* last app user */
#define AID_NET_BT_ADMIN 3001
#define AID_NET_BT 3002
#define AID_INET 3003
#define AID_EVERYBODY 9997
#define AID_APP 10000
#define AID_USER 100000

#define UNTRUSTED_APP_UID (AID_APP + 999)
#define UNTRUSTED_APP_GID (AID_APP + 999)

const char* const SELINUX_XATTR_NAME = "security.selinux";
const char* const SELINUX_CONTEXT_FILE = "/proc/thread-self/attr/current";
const char* const SELINUX_CONTEXT_UNTRUSTED_APP = "u:r:untrusted_app:s0:c512,c768";
const char* const SELINUX_CONTEXT_SYSTEM_APP = "u:r:untrusted_app:s0";

const char* const SELINUX_LABEL_APP_DATA_FILE = "u:object_r:app_data_file:s0";
const char* const SELINUX_LABLE_SYSTEM_DATA_FILE = "u:object_r:system_file:s0";

const gid_t UNTRUSTED_APP_GROUPS[] = {UNTRUSTED_APP_GID, AID_NET_BT_ADMIN, AID_NET_BT, AID_INET, AID_EVERYBODY};
const size_t UNTRUSTED_APP_NUM_GROUPS = sizeof(UNTRUSTED_APP_GROUPS) / sizeof(UNTRUSTED_APP_GROUPS[0]);

static struct option const longopts[] = {
        {"uid", required_argument, NULL, 'u'},
        {"gid", required_argument, NULL, 'g'},
        {"secontext", required_argument, NULL, 's'},
        {NULL, 0, NULL, 0}
};

static void
usage(void)
{
    const char*  str = "Usage: " PROGNAME " [-u/--user <uid>] [-s/--selinux <secontext>] <command> [<args>]\n";
    printf("*************************************************\n");
    printf("*************************************************\n\n");
    printf(str);
    printf("-u\t--user\t\t<uid>\n");
    printf("-g\t--group\t\t<gid>\n");
    printf("-s\t--selinux\t<secontext>, process selinux context\n");
    exit(1);
}

static void
panic(const char* format, ...)
{
    va_list args;
    fprintf(stderr, "[ERR] %s: ", PROGNAME);
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    exit(1);
}

static void
warning(const char* format, ...)
{
    va_list args;
    fprintf(stderr, "[WARN] %s: ", PROGNAME);
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
}

static char *guess_file_con(const char *pcon) {
        if (!strncmp(pcon, SELINUX_CONTEXT_SYSTEM_APP, strlen(SELINUX_CONTEXT_SYSTEM_APP)))
                return SELINUX_LABLE_SYSTEM_DATA_FILE;
        else if (!strncmp(pcon, SELINUX_CONTEXT_UNTRUSTED_APP, strlen(SELINUX_CONTEXT_UNTRUSTED_APP)))
                return SELINUX_LABEL_APP_DATA_FILE;
        else
                return NULL;
}

static int cmpfilecon(const char *path, const char *new) {
        char old_context[512] = {0};

        if (getxattr(path, SELINUX_XATTR_NAME, old_context, sizeof(old_context)) < 0)
                warning("comfilecon: getxattr paniced: %s\n", strerror(errno));

        return strncmp(new, old_context, strlen(old_context));
}

// Similar to libselinux setfilecon(3), but:
// - No library dependency
// - No dynamic memory allocation
// - Uses panic() instead of returning an error code
static void setfilecon(const char* path, const char* context)
{
        if (!cmpfilecon(path, context))
                return;

        if (setxattr(path, SELINUX_XATTR_NAME, context, strlen(context) + 1, 0) != 0)
                warning("setfilecon: setxattr paniced: %s\n", strerror(errno));

        if (cmpfilecon(path, context))
                warning("setfilecon: did not change file context\n");
}

//#include <selinux/selinux.h>

// Similar to libselinux getcon(3), but:
// - No library dependency
// - No dynamic memory allocation
// - Uses panic() instead of returning an error code
static void getcon(char* context, size_t context_size)
{
        int fd = open(SELINUX_CONTEXT_FILE, O_RDONLY);
        if (fd < 0)
                panic("getcon: couldn't open context file");

        ssize_t nread = read(fd, context, context_size);

        close(fd);

        if (nread <= 0)
                panic("getcon: paniced to read context file");

        // The contents of the context file MAY end with a newline
        // and MAY not have a null terminator.  Handle this here.
        if (context[nread - 1] == '\n')
                context[nread - 1] = '\0';
}

// Similar to libselinux setcon(3), but:
// - No library dependency
// - No dynamic memory allocation
// - Uses panic() instead of returning an error code
static void setcon(const char* context)
{
        char new_context[512];

        // Attempt to write the new context
        int fd = open(SELINUX_CONTEXT_FILE, O_WRONLY);

        if (fd < 0)
                panic("setcon: could not open context file");

        ssize_t bytes_written = write(fd, context, strlen(context));

        // N.B.: We cannot reuse this file descriptor, since the target SELinux context
        //       may not be able to read from it.
        close(fd);

        if (bytes_written != (ssize_t)strlen(context))
                panic("setcon: could not write entire context, wrote=%zi, expected=%zu", bytes_written, strlen(context));

        // Validate the transition by checking the context
        getcon(new_context, sizeof(new_context));

        if (strcmp(context, new_context) != 0)
                panic("setcon: paniced to change, want=%s, context=%s", context, new_context);
}

int main(int argc, char **argv)
{
    const char *userid = NULL, *groupid = NULL, *secontext = NULL;
    int myuid, uid, gid, is_app = 0, comm = 0;
        bool has_cmd;

    /* check arguments */
    if (argc < 3)
        usage();

    /* check userid of caller - must be 'root' */
    myuid = getuid();
    if (myuid != 0) {
        panic("only 'root' users can run this program\n");
    }

        while (1) {
                int c = getopt_long(argc, argv, "s:u:g:", longopts, NULL);
                if (c == -1)
                        break;

                switch (c) {
                case 's':
                        secontext = optarg;
                        break;
                case 'u':
                        userid = optarg;
                        break;
                case 'g':
                        groupid = optarg;
                        break;
                default:
                        usage();
                }
        }

        has_cmd = (optind < argc);

    /* retrieve userid and groupid if provided */
        if (userid) {
                uid = atoi(userid);
                if ((uid < 0) || (uid > AID_USER)) 
                        panic("invalid user id: %d\n", uid);
                if ((AID_APP_START < uid) && (uid < AID_APP_END))
                        is_app = 1;
        } 

        if (groupid) {
                gid = atoi(groupid);
                if ((gid < 0) || (gid > AID_USER)) 
                        panic("invalid group id: %d\n", gid);
                if ((AID_APP_START < gid) && (gid < AID_APP_END))
                        is_app = 1;
        }

        if (is_app && (setgroups(UNTRUSTED_APP_NUM_GROUPS, UNTRUSTED_APP_GROUPS) != 0))
                panic("set default untrusted_app groups failed: %s\n", strerror(errno));

        if (groupid && (setresgid(gid,gid,gid))) {
                panic("set gid denied: %s\n", strerror(errno));
                return 1;
        }

        if ((userid && (setresuid(uid,uid,uid)))) {
                panic("set uid denied: %s\n", strerror(errno));
                return 1;
        }

    /* setting selinux context on process if provided */
        if (secontext) {
                if (has_cmd) {
                        char *fcon = guess_file_con(secontext);
                        if (fcon) setfilecon(argv[optind], fcon);
                }
                setcon(secontext);
        }

    /* Default exec shell. */
        if (!has_cmd) {
        execlp("/system/bin/sh", "sh", NULL);
        panic("exec paniced: %s\n", strerror(errno));
        return 1;
        }

        // User specified command for exec.
        execvp(argv[optind], &argv[optind]);
    panic("exec paniced: %s\n", strerror(errno));
    return 1;
}
