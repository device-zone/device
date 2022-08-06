/**
 *    Copyright (C) 2021 Graham Leggett <minfrin@sharp.fm>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

/*
 * device-set - helper to set name value pairs
 *
 */

#include <apr.h>
#include <apr_escape.h>
#include <apr_file_io.h>
#include <apr_getopt.h>
#include <apr_lib.h>
#include <apr_hash.h>
#include <apr_strings.h>
#include <apr_uuid.h>
#include <apr_xlate.h>

#include "device_util.h"

#include "config.h"

#include <stdlib.h>
#if HAVE_UNISTD_H
#include <sys/types.h>
#include <unistd.h>
#endif
#if HAVE_GRP_H
#include <grp.h>
#endif
#if HAVE_PWD_H
#include <sys/types.h>
#include <pwd.h>
#endif

#define DEVICE_INDEX 257
#define DEVICE_PORT 258
#define DEVICE_UNPRIVILEGED_PORT 259
#define DEVICE_HOSTNAME 260
#define DEVICE_FQDN 261
#define DEVICE_SELECT 262
#define DEVICE_SELECT_BASE 263
#define DEVICE_BYTES 264
#define DEVICE_BYTES_MIN 265
#define DEVICE_BYTES_MAX 266
#define DEVICE_SYMLINK 267
#define DEVICE_SYMLINK_BASE 268
#define DEVICE_SYMLINK_SUFFIX 269
#define DEVICE_SQL_IDENTIFIER 270
#define DEVICE_SQL_DELIMITED_IDENTIFIER 271
#define DEVICE_SQL_IDENTIFIER_MIN 272
#define DEVICE_SQL_IDENTIFIER_MAX 273
#define DEVICE_USER_GROUP 274
#define DEVICE_USER 275
#define DEVICE_DISTINGUISHED_NAME 276

#define DEVICE_INDEX_SUFFIX ""
#define DEVICE_TXT_SUFFIX ".txt"
#define DEVICE_SQL_SUFFIX ".txt"
#define DEVICE_USER_SUFFIX ".txt"
#define DEVICE_DISTINGUISHED_NAME_SUFFIX ".txt"
#define DEVICE_NONE_SUFFIX ""

#define DEVICE_ADD_MARKER "added"
#define DEVICE_SET_MARKER "updated"
#define DEVICE_REMOVE_MARKER "removed"

typedef enum device_mode_e {
    DEVICE_SET,
    DEVICE_ADD,
    DEVICE_REMOVE,
    DEVICE_MARK
} device_mode_e;

typedef struct device_set_t {
    apr_pool_t *pool;
    apr_pool_t *tpool;
    apr_file_t *err;
    apr_file_t *in;
    apr_file_t *out;
    const char *key;
    const char *keypath;
    const char *keyval;
    apr_hash_t *pairs;
    const char *path;
    apr_array_header_t *user_groups;
    apr_array_header_t *select_bases;
    apr_array_header_t *symlink_bases;
    const char *symlink_suffix;
    int symlink_suffix_len;
    device_mode_e mode;
} device_set_t;

#define DEVICE_ERROR_MAX 80
#define DEVICE_ID_MAX 255
#define DEVICE_PORT_MIN 0
#define DEVICE_PORT_MAX 65535
#define DEVICE_PORT_UNPRIVILEGED_MIN 1025
#define DEVICE_PORT_UNPRIVILEGED_MAX 49151
#define DEVICE_HOSTNAME_MIN 1
#define DEVICE_HOSTNAME_MAX 63
#define DEVICE_SELECT_MAX 80
#define DEVICE_SELECT_NONE "none"
#define DEVICE_SYMLINK_MAX 80
#define DEVICE_SYMLINK_NONE "none"
#define DEVICE_SQL_IDENTIFIER_DEFAULT_MIN 1
#define DEVICE_SQL_IDENTIFIER_DEFAULT_MAX 63
#define DEVICE_FILE_UMASK (0x0113)

typedef enum device_pair_e {
    DEVICE_PAIR_INDEX,
    DEVICE_PAIR_PORT,
    DEVICE_PAIR_UNPRIVILEGED_PORT,
    DEVICE_PAIR_HOSTNAME,
    DEVICE_PAIR_FQDN,
    DEVICE_PAIR_SELECT,
    DEVICE_PAIR_BYTES,
    DEVICE_PAIR_SYMLINK,
    DEVICE_PAIR_SQL_IDENTIFIER,
    DEVICE_PAIR_SQL_DELIMITED_IDENTIFIER,
    DEVICE_PAIR_USER,
    DEVICE_PAIR_DISTINGUISHED_NAME
} device_pair_e;

typedef enum device_optional_e {
    DEVICE_OPTIONAL,
    DEVICE_REQUIRED
} device_optional_e;

typedef enum device_index_e {
    DEVICE_NORMAL,
    DEVICE_INDEXED
} device_index_e;

typedef struct device_pair_selects_t {
    apr_array_header_t *bases;
} device_pair_selects_t;

typedef struct device_pair_bytes_t {
    apr_int64_t min;
    apr_int64_t max;
} device_pair_bytes_t;

typedef struct device_pair_symlinks_t {
    apr_array_header_t *bases;
} device_pair_symlinks_t;

typedef struct device_pair_sqlid_t {
    apr_int64_t min;
    apr_int64_t max;
} device_pair_sqlid_t;

typedef struct device_pair_users_t {
    apr_array_header_t *groups;
} device_pair_users_t;

typedef struct device_pair_t {
    const char *key;
    const char *suffix;
    device_pair_e type;
    device_optional_e optional;
    device_index_e index;
    union {
        device_pair_bytes_t b;
        device_pair_selects_t sl;
        device_pair_symlinks_t s;
        device_pair_sqlid_t q;
        device_pair_users_t u;
    };
} device_pair_t;

typedef struct device_file_t {
    const char *key;
    char *template;
    const char *dest;
    const char *backup;
    const char *val;
    device_index_e index;
    apr_filetype_e type;
} device_file_t;

static const apr_getopt_option_t
    cmdline_opts[] =
{
    /* commands */
    { "help", 'h', 0, "  -h, --help\t\t\tDisplay this help message." },
    { "version", 'v', 0,
        "  -v, --version\t\t\tDisplay the version number." },
    { "base", 'b', 1, "  -b, --base=path\t\tBase path in which to search for option files." },
    { "complete", 'c', 0, "  -c, --complete\t\tPerform command line completion." },
    { "optional", 'o', 0, "  -o, --optional\t\tOptions declared after this are optional. This\n\t\t\t\tis the default." },
    { "required", 'r', 0, "  -r, --required\t\tOptions declared after this are required." },
    { "add", 'a', 1, "  -a, --add=name\t\tAdd a new set of options, named by the key\n\t\t\t\tspecified, which becomes required. A file \n\t\t\t\tcalled '" DEVICE_ADD_MARKER "' will be created in the newly\n\t\t\t\tcreated directory to indicate the directory\n\t\t\t\tshould be processed." },
    { "remove", 'd', 1, "  -d, --remove=name\t\tRemove a set of options, named by the key\n\t\t\t\tspecified. The removal takes place immediately." },
    { "mark", 'm', 1, "  -m, --mark=name\t\tMark a set of options for removal, named by the\n\t\t\t\tkey specified. The actual removal is expected\n\t\t\t\tto be done by the script that processes this\n\t\t\t\toption. A file called '" DEVICE_REMOVE_MARKER "' will be created\n\t\t\t\tin the directory to indicate the directory\n\t\t\t\tshould be processed for removal." },
    { "set", 's', 1, "  -s, --set\t\t\tSet an option among a set of options, named by\n\t\t\t\tthe key specified. A file called '" DEVICE_SET_MARKER "' is\n\t\t\t\tcreated to indicate that settings should be\n\t\t\t\tprocessed for update." },
    { "index", DEVICE_INDEX, 1, "  --index=name\t\t\tSet the index of this option within a set of\n\t\t\t\toptions. If set to a positive integer starting\n\t\t\t\tfrom zero, this option will be inserted at the\n\t\t\t\tgiven index and higher options moved one up to\n\t\t\t\tfit. If unset, or if larger than the index of\n\t\t\t\tthe last option, this option will be set as the\n\t\t\t\tlast option and others moved down to fit. If\n\t\t\t\tnegative, the option will be inserted at the\n\t\t\t\tend counting backwards." },
    { "port", DEVICE_PORT, 1, "  --port=name\t\t\tParse a port. Ports are integers in the range\n\t\t\t\t0 to 65535." },
    { "unprivileged-port", DEVICE_UNPRIVILEGED_PORT, 1, "  --unprivileged-port=name\tParse an unprivileged port. Unprivileged ports\n\t\t\t\tare integers in the range 1025 to 49151." },
    { "hostname", DEVICE_HOSTNAME, 1, "  --hostname=name\t\tParse a hostname. Hostnames consist of the\n\t\t\t\tcharacters a-z, 0-9, or a hyphen. Hostname\n\t\t\t\tcannot start with a hyphen." },
    { "fqdn", DEVICE_FQDN, 1, "  --fqdn=name\t\t\tParse a fully qualified domain name. FQDNs\n\t\t\t\tconsist of labels containing the characters\n\t\t\t\ta-z, 0-9, or a hyphen, and cannot start with\n\t\t\t\ta hyphen. Labels are separated by dots, and\n\t\t\t\tthe total length cannot exceed 253 characters." },
    { "select-base", DEVICE_SELECT_BASE, 1, "  --select-base=file\t\tBase files containing options for possible\n\t\t\t\tselections. More than one file can be specified." },
    { "select", DEVICE_SELECT, 1, "  --select=name\t\t\tParse a selection from a file containing\n\t\t\t\toptions. The file containing options is\n\t\t\t\tsearched relative to the base path, and has\n\t\t\t\tthe same name as the result file. Unambiguous\n\t\t\t\tprefix matches are accepted." },
    { "bytes-minimum", DEVICE_BYTES_MIN, 1, "  --bytes-minimum=bytes\t\tLower limit used by the next bytes option. Zero\n\t\t\t\tfor no limit." },
    { "bytes-maximum", DEVICE_BYTES_MAX, 1, "  --bytes-maximum=bytes\t\tUpper limit used by the next bytes option. Zero\n\t\t\t\tfor no limit." },
    { "bytes", DEVICE_BYTES, 1, "  --bytes=name\t\t\tParse a positive integer containing bytes.\n\t\t\t\tOptional modifiers like B, kB, KiB, MB, MiB,\n\t\t\t\tGB, GiB, TB, TiB, PB, PiB, EB, EiB are accepted,\n\t\t\t\tand the given string is expanded into a byte\n\t\t\t\tvalue. Modifiers outside of the specified byte\n\t\t\t\trange are ignored." },
    { "symlink-base", DEVICE_SYMLINK_BASE, 1, "  --symlink-base=path\t\tBase path containing targets for symbolic links.\n\t\t\t\tMore than one path can be specified. In the case\n\t\t\t\tof collision, the earliest match wins." },
    { "symlink-suffix", DEVICE_SYMLINK_SUFFIX, 1, "  --symlink-suffix=suffix\tLimit targets for symbolic links to this suffix." },
    { "symlink", DEVICE_SYMLINK, 1, "  --symlink=name\t\tParse a selection from a list of files or\n\t\t\t\tdirectories matching the symlink-path, and save\n\t\t\t\tthe result as a symlink. If optional, the special\n\t\t\t\tvalue 'none' is accepted to mean no symlink." },
    { "sql-id", DEVICE_SQL_IDENTIFIER, 1, "  --sql-id=id\t\t\tSQL identifier in regular format. Regular\n\t\t\t\tidentifiers start with a letter (a-z, but also\n\t\t\t\tletters with diacritical marks and non-Latin\n\t\t\t\tletters) or an underscore (_). Subsequent\n\t\t\t\tcharacters in an identifier can be letters,\n\t\t\t\tunderscores, or digits (0-9). The resulting value\n\t\t\t\tdoes not need to be SQL escaped before use." },
    { "sql-delimited-id", DEVICE_SQL_DELIMITED_IDENTIFIER, 1, "  --sql-delimited-id=id\t\tSQL identifier in delimited format. Delimited\n\t\t\t\tidentifiers consist of any UTF8 non-zero character.\n\t\t\t\tThe resulting value must be SQL escaped separately\n\t\t\t\tbefore use." },
    { "sql-id-minimum", DEVICE_SQL_IDENTIFIER_MIN, 1, "  --sql-id-minimum=chars\tMinimum length used by the next\n\t\t\t\tsql-id/sql-delimited-id option. Defaults to 1." },
    { "sql-id-maximum", DEVICE_SQL_IDENTIFIER_MAX, 1, "  --sql-id-maximum=chars\tMaximum length used by the next\n\t\t\t\tsql-id/sql-delimited-id option. Defaults to 63." },
    { "user-group", DEVICE_USER_GROUP, 1, "  --unix-group=name\t\tLimit usernames to members of the given group. May\n\t\t\t\tbe specified more than once." },
    { "user", DEVICE_USER, 1, "  --user=name\t\t\tParse a user that exists on the system." },
    { "distinguished-name", DEVICE_DISTINGUISHED_NAME, 1, "  --distinguished-name=name\tParse an RFC4514 Distinguished Name." },
    { NULL }
};

static int help(apr_file_t *out, const char *name, const char *msg, int code,
        const apr_getopt_option_t opts[])
{
    const char *n;
    int i = 0;

    n = strrchr(name, '/');
    if (!n) {
        n = name;
    }
    else {
        n++;
    }

    apr_file_printf(out,
            "%s\n"
            "\n"
            "NAME\n"
            "  %s - Device shell set helper.\n"
            "\n"
            "SYNOPSIS\n"
            "  %s [-v] [-h] [commands ...]\n"
            "\n"
            "DESCRIPTION\n"
            "  The device shell set helper sets name value pairs of various types in\n"
            "  the current directory. It is expected to be called from device scripts.\n"
            "\n"
            "  Use options to define the types of values accepted and the names assigned\n"
            "  to them. Each value will be sanity checked based on the given type, and an\n"
            "  error returned if not valid.\n"
            "\n"
            "OPTIONS\n", msg ? msg : "", n, n);

    while (opts[i].name) {
        apr_file_printf(out, "%s\n\n", opts[i].description);
        i++;
    }

    apr_file_printf(out,
            "RETURN VALUE\n"
            "  The device shell returns a non zero exit code on error.\n"
            "\n"
            "EXAMPLES\n"
            "  In this example, set a host to the value 'localhost', and a port to\n"
            "  the value '22'. These values will be saved to files in the current\n"
            "  directory named 'host.txt' and 'port.txt' respectively.\n"
            "\n"
            "\t~$ device-set --hostname host --port port -- host localhost port 22\n"
            "\n"
            "  Here we perform command line completion on the given option. Note that\n"
            "  the option passed is empty, and thus matches both possible options.\n"
            "\n"
            "\t~$ device-set --hostname host --port port -c ''\n"
            "\thost\n"
            "\tport\n"
            "\n"
            "AUTHOR\n"
            "  Graham Leggett <minfrin@sharp.fm>\n");

    return code;
}

static int version(apr_file_t *out)
{
    apr_file_printf(out, PACKAGE_STRING "\n");

    return 0;
}

static int abortfunc(int retcode)
{
    fprintf(stderr, "Out of memory.\n");

    return retcode;
}

static void device_error_possibles(device_set_t *ds, const char *arg, apr_array_header_t *possibles)
{
    if (possibles->nelts && possibles->nelts < DEVICE_ERROR_MAX) {
        apr_file_printf(ds->err, "%s: must be one of: %s\n",
            apr_pescape_echo(ds->pool, arg, 1),
            apr_array_pstrcat(ds->pool, possibles, ','));
    }
    else {
        apr_file_printf(ds->err, "%s: value does not match.\n",
            apr_pescape_echo(ds->pool, arg, 1));
    }
}

/*
 * Map string to a safe filename.
 *
 * Remove invalid characters from the name of the file.
 */
static const char *device_safename(apr_pool_t *pool, const char *name)
{
    char *safe = apr_palloc(pool, strlen(name) + 1);

    int i;

    for (i = 0; name[i]; i++) {

        switch (name[i]) {
        case '/':
        case '\\':
            safe[i] = '_';
            break;
        default:
            safe[i] = name[i];
        }
    }

    safe[i] = 0;

    return safe;
}

/*
 * Index is an integer between APR_INT64_MIN and APR_INT64_MAX inclusive.
 */
static apr_status_t device_parse_index(device_set_t *ds, device_pair_t *pair,
        const char *arg, const char **option)
{
    char *end;

    if (!arg || !arg[0]) {
        apr_file_printf(ds->err, "argument '%s': is empty.\n",
                apr_pescape_echo(ds->pool, pair->key, 1));
        return APR_INCOMPLETE;
    }

    apr_int64_t index = apr_strtoi64(arg, &end, 10);
    if (end[0] || errno == ERANGE) {
        apr_file_printf(ds->err, "argument '%s': '%s' is not a valid index.\n",
                apr_pescape_echo(ds->pool, pair->key, 1),
                apr_pescape_echo(ds->pool, arg, 1));
        return APR_EINVAL;
    }
    if (option) {
        *option = apr_psprintf(ds->pool, "%" APR_INT64_T_FMT, index);
    }
    return APR_SUCCESS;
}

/*
 * Port is an integer between 0 and 65535 inclusive.
 */
static apr_status_t device_parse_port(device_set_t *ds, device_pair_t *pair,
        const char *arg)
{
    char *end;

    if (!arg || !arg[0]) {
        apr_file_printf(ds->err, "argument '%s': is empty.\n",
                apr_pescape_echo(ds->pool, pair->key, 1));
        return APR_INCOMPLETE;
    }

    apr_int64_t port = apr_strtoi64(arg, &end, 10);
    if (end[0] || port < DEVICE_PORT_MIN || port > DEVICE_PORT_MAX) {
        apr_file_printf(ds->err, "argument '%s': '%s' is not a valid port.\n",
                apr_pescape_echo(ds->pool, pair->key, 1),
                apr_pescape_echo(ds->pool, arg, 1));
        return APR_EINVAL;
    }
    return APR_SUCCESS;
}

/*
 * Port is an integer between 1025 and 49151 inclusive.
 */
static apr_status_t device_parse_unprivileged_port(device_set_t *ds,
        device_pair_t *pair, const char *arg)
{
    char *end;

    if (!arg || !arg[0]) {
        apr_file_printf(ds->err, "argument '%s': is empty.\n",
                apr_pescape_echo(ds->pool, pair->key, 1));
        return APR_INCOMPLETE;
    }

    apr_int64_t port = apr_strtoi64(arg, &end, 10);
    if (end[0] || port < DEVICE_PORT_UNPRIVILEGED_MIN || port > DEVICE_PORT_UNPRIVILEGED_MAX) {
        apr_file_printf(ds->err, "argument '%s': '%s' is not a valid unprivileged port.\n",
                apr_pescape_echo(ds->pool, pair->key, 1),
                apr_pescape_echo(ds->pool, arg, 1));
        return APR_EINVAL;
    }
    return APR_SUCCESS;
}

/*
 * Hostname is a string of up to and including 63 characters in length, containing
 * 0-9, a-z, a hyphen, but no hyphen at start of string.
 *
 * https://man7.org/linux/man-pages/man7/hostname.7.html
 */
static apr_status_t device_parse_hostname(device_set_t *ds, device_pair_t *pair,
        const char *arg)
{
    int len = 0;

    if (!arg || !arg[0]) {
        apr_file_printf(ds->err, "argument '%s': is empty.\n",
                apr_pescape_echo(ds->pool, pair->key, 1));
        return APR_INCOMPLETE;
    }

    while (arg[len]) {
        char c = arg[len++];

        if (c >= '0' && c <= '9') {
            /* ok */
        }
        else if (c >= 'a' && c <= 'z') {
            /* ok */
        }
        else if (c == '-') {
            if (len == 1) {
                /* first character cannot be a hyphen */
                apr_file_printf(ds->err, "argument '%s': first character cannot be a hyphen.\n",
                        apr_pescape_echo(ds->pool, pair->key, 1));
                return APR_EINVAL;
            }
            else {
                /* ok */
            }
        }
        else {
            /* not ok */
            apr_file_printf(ds->err, "argument '%s': '%c' is an invalid character.\n",
                    apr_pescape_echo(ds->pool, pair->key, 1), c);
            return APR_EINVAL;
        }

        if (len == 64) {
            /* not ok */
            apr_file_printf(ds->err, "argument '%s': '%s' is too long.\n",
                    apr_pescape_echo(ds->pool, pair->key, 1),
                    apr_pescape_echo(ds->pool,
                            apr_pstrcat(ds->pool,
                                    apr_pstrndup(ds->pool, arg, 64), "...",
                                    NULL), 1));
            return APR_EINVAL;
        }
    }

    return APR_SUCCESS;
}

/*
 * Fully Qualified Domain Name is a series of hostnames (defined above),
 * separated by dots '.', and with a length no larger than 253 characters
 * inclusive.
 */
static apr_status_t device_parse_fqdn(device_set_t *ds, device_pair_t *pair,
        const char *arg)
{
    int len = 0, hlen = 0;

    if (!arg || !arg[0]) {
        apr_file_printf(ds->err, "argument '%s': is empty.\n",
                apr_pescape_echo(ds->pool, pair->key, 1));
        return APR_INCOMPLETE;
    }

    while (arg[len]) {
        char c = arg[len++];
        hlen++;

        if (c == '.') {
            if (len == 1) {
                /* not ok */
                apr_file_printf(ds->err, "argument '%s': domain name starts with a dot.\n",
                        apr_pescape_echo(ds->pool, pair->key, 1));
                return APR_EINVAL;
            }
            else if (hlen == 1) {
                /* not ok */
                apr_file_printf(ds->err, "argument '%s': domain name contains consecutive dots.\n",
                        apr_pescape_echo(ds->pool, pair->key, 1));
                return APR_EINVAL;
            }
            hlen = 0;
        }
        else if (c >= '0' && c <= '9') {
            /* ok */
        }
        else if (c >= 'a' && c <= 'z') {
            /* ok */
        }
        else if (c == '-') {
            if (len == 1) {
                /* first character cannot be a hyphen */
                apr_file_printf(ds->err, "argument '%s': first character cannot be a hyphen.\n",
                        apr_pescape_echo(ds->pool, pair->key, 1));
                return APR_EINVAL;
            }
            else {
                /* ok */
            }
        }
        else {
            /* not ok */
            apr_file_printf(ds->err, "argument '%s': '%c' is an invalid character.\n",
                    apr_pescape_echo(ds->pool, pair->key, 1), c);
            return APR_EINVAL;
        }

        if (hlen == 64) {
            /* not ok */
            apr_file_printf(ds->err, "argument '%s': label '%s' is too long.\n",
                    apr_pescape_echo(ds->pool, pair->key, 1),
                    apr_pescape_echo(ds->pool,
                            apr_pstrcat(ds->pool,
                                    apr_pstrndup(ds->pool, arg, 64), "...",
                                    NULL), 1));
            return APR_EINVAL;
        }

        if (len == 254) {
            /* not ok */
            apr_file_printf(ds->err, "argument '%s': domain name is longer than 253 characters.\n",
                    apr_pescape_echo(ds->pool, pair->key, 1));
            return APR_EINVAL;
        }
    }

    return APR_SUCCESS;
}

/**
 * Select is a string which must match one of a series of strings read line
 * by line from a file containing a fixed set of possible options.
 */
static apr_status_t device_parse_select(device_set_t *ds, device_pair_t *pair,
        const char *arg, apr_array_header_t *options, const char **option)
{
    const char *none = NULL;
    apr_file_t *in;
    apr_off_t end = 0, start = 0;
    apr_status_t status;
    apr_size_t arglen = arg ? strlen(arg) : 0;

    apr_array_header_t *possibles = apr_array_make(ds->pool, 10, sizeof(char *));

    int i;

    if (option) {
        option[0] = NULL; /* until further notice */
    }

    if (!pair->sl.bases) {
        apr_file_printf(ds->err, "no base directory specified for '%s'\n", pair->key);
        return APR_EGENERAL;
    }

    if (pair->optional == DEVICE_OPTIONAL) {
        none = DEVICE_SELECT_NONE;
    }

    for (i = 0; i < pair->sl.bases->nelts; i++) {

        const char *base = APR_ARRAY_IDX(pair->sl.bases, i, const char *);

        /* open the options */
        if (APR_SUCCESS
                != (status = apr_file_open(&in, base, APR_FOPEN_READ,
                        APR_FPROT_OS_DEFAULT, ds->pool))) {
            apr_file_printf(ds->err, "cannot open options '%s': %pm\n", pair->key,
                    &status);
        }

        /* how long are the options? */
        else if (APR_SUCCESS
                != (status = apr_file_seek(in, APR_END, &end))) {
            apr_file_printf(ds->err, "cannot seek end of options '%s': %pm\n", pair->key,
                    &status);
        }

        /* back to the beginning */
        else if (APR_SUCCESS
                != (status = apr_file_seek(in, APR_SET, &start))) {
            apr_file_printf(ds->err, "cannot seek end of options '%s': %pm\n", pair->key,
                    &status);
        }

        else {
            int size = end + 1;
            char *buffer = apr_palloc(ds->pool, size);

            apr_array_header_t *possibles = apr_array_make(ds->pool, 10, sizeof(char *));

            do {

                const char **possible;
                apr_size_t optlen;
                int exact;

                if (none) {
                    strcpy(buffer, DEVICE_SELECT_NONE);
                } else {
                    status = apr_file_gets(buffer, size, in);
                    if (status != APR_SUCCESS) {
                        break;
                    }
                }
                optlen = strlen(buffer);

                /* chop trailing newline */
                if (optlen && buffer[optlen - 1] == '\n') {
                    optlen--;
                    buffer[optlen] = 0;
                }

                if (!buffer[0] || buffer[0] == '#' || apr_isspace(buffer[0])) {
                    continue;
                }

                possible = apr_array_push(possibles);
                possible[0] = apr_pstrdup(ds->pool, buffer);

                exact = (0 == strcmp(arg, buffer));

                if (!strncmp(arg, buffer, arglen)) {

                    const char **opt;

                    if (exact) {
                        apr_array_clear(options);
                    }

                    opt = apr_array_push(options);
                    opt[0] = apr_pstrcat(ds->pool,
                            pair->optional == DEVICE_OPTIONAL ? "-" : "*",
                            device_pescape_shell(ds->pool, pair->key), "=",
                            device_pescape_shell(ds->pool, buffer),
                            NULL);

                    if (option) {
                        if (none) {
                            option[0] = NULL;
                        }
                        else {
                            option[0] = possible[0];
                        }
                    }
                }

                if (exact) {
                    /* exact matches short circuit */
                    break;
                }

                none = NULL;

            } while (1);

            apr_file_close(in);

            if (APR_SUCCESS == status) {
                /* short circuit, all good */
                break;
            }
            else if (APR_EOF == status) {
                /* loop around */
                status = APR_SUCCESS;
            }
            else {
                apr_file_printf(ds->err, "cannot read option '%s': %pm\n", pair->key,
                        &status);
                return status;
            }
        }

    }

    if (option && option[0]) {
        if (options->nelts == 1) {
            /* all ok */
        }
        else {
            device_error_possibles(ds, pair->key, possibles);
            return APR_INCOMPLETE;
        }
    }

    return status;
}

/*
 * Bytes is a positive integer.
 *
 * We understand the modifiers K(1024), M(1024)
 */
static apr_status_t device_parse_bytes(device_set_t *ds, device_pair_t *pair,
        const char *arg, apr_array_header_t *options, const char **option)
{
    char *end;
    char *result;
    apr_int64_t bytes;

    apr_array_header_t *possibles = apr_array_make(ds->pool, 10, sizeof(char *));

    if (!arg || !arg[0]) {
        apr_file_printf(ds->err, "argument '%s': is empty.\n",
                apr_pescape_echo(ds->pool, pair->key, 1));
        return APR_INCOMPLETE;
    }

    if (arg[0] == '-') {
        apr_file_printf(ds->err, "argument '%s': number must be positive.\n",
                apr_pescape_echo(ds->pool, pair->key, 1));
        return APR_EINVAL;
    }

    if (!apr_isdigit(arg[0])) {
        apr_file_printf(ds->err, "argument '%s': is not a number.\n",
                apr_pescape_echo(ds->pool, pair->key, 1));
        return APR_EINVAL;
    }

    bytes = apr_strtoi64(arg, &end, 10);

    if (end - arg > 18) {
        apr_file_printf(ds->err, "argument '%s': number is too long.\n",
                apr_pescape_echo(ds->pool, pair->key, 1));
        return APR_EINVAL;
    }

    /* zero - short circuit the suffixes */
    if (!end[0] && bytes == 0) {
        if (pair->b.min > 0) {
            apr_file_printf(ds->err, "argument '%s': too small.\n",
                    apr_pescape_echo(ds->pool, pair->key, 1));
            return APR_EINVAL;
        }
        if (option) {
            option[0] = arg;
        }
        return APR_SUCCESS;
    }


#define DEVICE_SET_BYTES(unit,expanded,limit) \
    if (!strncmp(end, unit, strlen(end)) && (limit)) { \
        if (!((pair->b.min && expanded < pair->b.min) || (pair->b.max && expanded > pair->b.max))) { \
            const char **opt = apr_array_push(options); \
            const char **possible = apr_array_push(possibles); \
            opt[0] = apr_psprintf(ds->pool, "%c%s=%.*s%s", \
                    pair->optional == DEVICE_OPTIONAL ? '-' : '*', \
                            device_pescape_shell(ds->pool, pair->key), \
                            (int)(end - arg), arg, unit); \
            possible[0] = apr_psprintf(ds->pool, "%.*s%s", (int)(end - arg), arg, unit); \
            result = apr_psprintf(ds->pool, "%" APR_INT64_T_FMT, (apr_int64_t)expanded); \
        } \
    } /* last line of macro... */


#define BYTE1024POW1 1024
#define BYTE1024POW2 1048576
#define BYTE1024POW3 1073741824
#define BYTE1024POW4 1099511627776
#define BYTE1024POW5 1125899906842624
#define BYTE1024POW6 1152921504606846976
#define BYTE1024POW7 1180591620717411303424
#define BYTE1024POW8 1208925819614629174706176

#define BYTE1000POW1 1000
#define BYTE1000POW2 1000000
#define BYTE1000POW3 1000000000
#define BYTE1000POW4 1000000000000
#define BYTE1000POW5 1000000000000000
#define BYTE1000POW6 1000000000000000000
#define BYTE1000POW7 1000000000000000000000
#define BYTE1000POW8 1000000000000000000000000

    /* bytes */
    DEVICE_SET_BYTES("B",
            (bytes), bytes < (apr_int64_t)4*(BYTE1024POW6));

    /* 1000    kB    kilobyte */
    DEVICE_SET_BYTES("kB",
            (bytes * BYTE1000POW1), bytes < (apr_int64_t)4*(BYTE1000POW5));

    /* 1024    KiB    kibibyte */
    DEVICE_SET_BYTES("KiB",
            (bytes * BYTE1024POW1), bytes < (apr_int64_t)4*(BYTE1024POW5));

    /* 1000^2    MB    megabyte 1000000 */
    DEVICE_SET_BYTES("MB",
            (bytes * BYTE1000POW2), bytes < (apr_int64_t)4*(BYTE1000POW4));

    /* 1024^2    MiB    mebibyte 1048576 */
    DEVICE_SET_BYTES("MiB",
            (bytes * BYTE1024POW2), bytes < (apr_int64_t)4*(BYTE1024POW4));

    /* 1000^3    GB    gigabyte 1000000000 */
    DEVICE_SET_BYTES("GB",
            (bytes * BYTE1000POW3), bytes < (apr_int64_t)4*(BYTE1000POW3));

    /* 1024^3    GiB    gibibyte 1073741824 */
    DEVICE_SET_BYTES("GiB",
            (bytes * BYTE1024POW3), bytes < (apr_int64_t)4*(BYTE1024POW3));

    /* 1000^4    TB    terabyte 1000000000000 */
    DEVICE_SET_BYTES("TB",
            (bytes * BYTE1000POW4), bytes < (apr_int64_t)4*(BYTE1000POW2));

    /* 1024^4    TiB    tebibyte 1099511627776 */
    DEVICE_SET_BYTES("TiB",
            (bytes * BYTE1024POW4), bytes < (apr_int64_t)4*(BYTE1024POW2));

    /* 1000^5    PB    petabyte 1000000000000000 */
    DEVICE_SET_BYTES("PB",
            (bytes * BYTE1000POW5), bytes < (apr_int64_t)4*BYTE1000POW1);

    /* 1024^5    PiB    pebibyte 1125899906842624 */
    DEVICE_SET_BYTES("PiB",
            (bytes * BYTE1024POW5), bytes < (apr_int64_t)4*BYTE1024POW1);

    /* 1000^6    EB    exabyte 1000000000000000000 */
    DEVICE_SET_BYTES("EB",
            (bytes * BYTE1000POW6), bytes < 4);

    /* 1024^6    EiB    exbibyte 1152921504606846976 */
    DEVICE_SET_BYTES("EiB",
            (bytes * BYTE1024POW6), bytes < 4);

    /* not until 128 bit integers */
#if 0
    /* 1000^7    ZB    zettabyte 1000000000000000000000 */
    DEVICE_SET_BYTES("ZB",
            (bytes * BYTE1000POW7), bytes < 1);

    /* 1024^7    ZiB    zebibyte 1180591620717411303424 */
    DEVICE_SET_BYTES("ZiB",
            (bytes * BYTE1024POW7), bytes < 1);

    /* 1000^8    YB    yottabyte 1000000000000000000000000 */
    DEVICE_SET_BYTES("YB",
            (bytes * BYTE1000POW8), bytes < 1);

    /* 1024^8    YiB    yobibyte  1208925819614629174706176 */
    DEVICE_SET_BYTES("YiB",
            (bytes * BYTE1024POW18), bytes < 1);
#endif

    /* no trailing characters, we are ok */
    if (!end[0]) {
        if (pair->b.min && pair->b.max && (bytes < pair->b.min || bytes > pair->b.max)) {
            apr_file_printf(ds->err, "argument '%s': number must be from %" APR_INT64_T_FMT " to %" APR_INT64_T_FMT ".\n",
                    apr_pescape_echo(ds->pool, pair->key, 1),
                    pair->b.min, pair->b.max);
            return APR_EINVAL;
        }
        else if (pair->b.min && bytes < pair->b.min) {
            apr_file_printf(ds->err, "argument '%s': number must be %" APR_INT64_T_FMT " or higher.\n",
                    apr_pescape_echo(ds->pool, pair->key, 1),
                    pair->b.min);
            return APR_EINVAL;
        }
        else if (pair->b.max && bytes > pair->b.max) {
            apr_file_printf(ds->err, "argument '%s': number must be %" APR_INT64_T_FMT " or lower.\n",
                    apr_pescape_echo(ds->pool, pair->key, 1),
                    pair->b.max);
            return APR_EINVAL;
        }
        if (option) {
            option[0] = arg;
        }
        return APR_SUCCESS;
    }

    /* trailing characters, but no possible options - we're invalid */
    if (options->nelts == 0) {
        if (pair->b.min && pair->b.max) {
            apr_file_printf(ds->err, "argument '%s': number must be from %" APR_INT64_T_FMT " to %" APR_INT64_T_FMT ".\n",
                    apr_pescape_echo(ds->pool, pair->key, 1),
                    pair->b.min, pair->b.max);
        }
        else if (pair->b.min) {
            apr_file_printf(ds->err, "argument '%s': number must be %" APR_INT64_T_FMT " or higher.\n",
                    apr_pescape_echo(ds->pool, pair->key, 1),
                    pair->b.min);
        }
        else if (pair->b.max) {
            apr_file_printf(ds->err, "argument '%s': number must be %" APR_INT64_T_FMT " or lower.\n",
                    apr_pescape_echo(ds->pool, pair->key, 1),
                    pair->b.max);
        }
        else {
            apr_file_printf(ds->err, "argument '%s': suffix not recognised.\n",
                    apr_pescape_echo(ds->pool, pair->key, 1));
        }
        return APR_EINVAL;
    }

    /* just one option, success */
    else if (options->nelts == 1) {
        if (option) {
            option[0] = result;
        }
        return APR_SUCCESS;
    }

    /* more than one option, we're incomplete */
    device_error_possibles(ds, pair->key, possibles);

    return APR_INCOMPLETE;
}

/**
 * Symlink is a name that will be linked to a series of files or directories at
 * a target path.
 */
static apr_status_t device_parse_symlink(device_set_t *ds, device_pair_t *pair,
        const char *arg, apr_array_header_t *options, const char **option)
{
    const char *none = NULL;
    apr_status_t status;
    apr_size_t arglen = arg ? strlen(arg) : 0;

    apr_array_header_t *possibles = apr_array_make(ds->pool, 10, sizeof(char *));

    int i;

    if (option) {
        option[0] = NULL; /* until further notice */
    }

    if (!pair->s.bases) {
        apr_file_printf(ds->err, "no base directory specified for '%s'\n", pair->key);
        return APR_EGENERAL;
    }

    if (pair->optional == DEVICE_OPTIONAL) {
        none = DEVICE_SYMLINK_NONE;
    }

    for (i = 0; i < pair->s.bases->nelts; i++) {

        apr_dir_t *thedir;
        apr_finfo_t dirent;

        const char *base = APR_ARRAY_IDX(pair->s.bases, i, const char *);

        if ((status = apr_dir_open(&thedir, base, ds->pool)) != APR_SUCCESS) {
            /* could not open directory, skip */
            continue;
        }

        do {
            const char **possible;
            char *name;

            if (none) {
                dirent.name = none;
                dirent.filetype = APR_REG;

                name = apr_pstrdup(ds->pool, dirent.name);
            } else {

                status = apr_dir_read(&dirent,
                        APR_FINFO_TYPE | APR_FINFO_NAME | APR_FINFO_WPROT, thedir);
                if (APR_STATUS_IS_INCOMPLETE(status)) {
                    continue; /* ignore un-stat()able files */
                } else if (status != APR_SUCCESS) {
                    break;
                }

                /* hidden files are ignored */
                if (dirent.name[0] == '.') {
                    continue;
                }

                /* suffixes? */
                if (ds->symlink_suffix) {
                    int len = strlen(dirent.name);
                    if (len < ds->symlink_suffix_len
                            || strcmp(ds->symlink_suffix,
                                    dirent.name + len - ds->symlink_suffix_len)) {
                        continue;
                    }
                    name = apr_pstrndup(ds->pool, dirent.name,
                            len - ds->symlink_suffix_len);
                }
                else {
                    name = apr_pstrdup(ds->pool, dirent.name);
                }
            }

            switch (dirent.filetype) {
            case APR_LNK:
            case APR_REG:
            case APR_DIR: {

                int exact = (0 == strcmp(arg, name));

                possible = apr_array_push(possibles);
                possible[0] = name;

                if (!strncmp(arg, name, arglen)) {

                    const char **opt;

                    if (exact) {
                        apr_array_clear(options);
                    }

                    opt = apr_array_push(options);
                    opt[0] = apr_pstrcat(ds->pool,
                            pair->optional == DEVICE_OPTIONAL ? "-" : "*",
                            device_pescape_shell(ds->pool, pair->key), "=",
                            device_pescape_shell(ds->pool, name),
                            NULL);

                    if (option) {

                        char *target;

                        if (none) {
                            option[0] = NULL;
                        }
                        else if (APR_SUCCESS
                                != (status = apr_filepath_merge(&target, base,
                                        apr_pstrcat(ds->pool, name, pair->suffix, NULL),
                                        APR_FILEPATH_NATIVE, ds->pool))) {
                            apr_file_printf(ds->err, "cannot merge links '%s': %pm\n", pair->key,
                                    &status);
                        }
                        else {
                            option[0] = target;
                        }

                    }
                }

                if (exact) {

                    /* exact matches short circuit */
                    apr_dir_close(thedir);

                    goto done;
                }

                break;
            }
            default:
                break;
            }

            none = NULL;

        } while (1);

        apr_dir_close(thedir);

    }
done:

    if (APR_SUCCESS == status) {
        /* short circuit, all good */
    }
    else if (APR_STATUS_IS_ENOENT(status)) {

        if (option) {
            if (options->nelts == 1) {
                /* all ok */
            }
            else {
                device_error_possibles(ds, pair->key, possibles);

                return APR_INCOMPLETE;
            }
        }

        status = APR_SUCCESS;
    }
    else {
        apr_file_printf(ds->err, "cannot read option '%s': %pm\n", pair->key,
                &status);
    }

    return status;
}

/*
 * Parse a positive integer.
 */
static apr_status_t device_parse_int64(device_set_t *ds, const char *arg,
        apr_int64_t *result)
{
    char *end;
    apr_int64_t bytes;

    if (!arg || !arg[0]) {
        apr_file_printf(ds->err, "number is empty.\n");
        return APR_INCOMPLETE;
    }

    if (arg[0] == '-') {
        apr_file_printf(ds->err, "number '%s' must be positive.\n",
                apr_pescape_echo(ds->pool, arg, 1));
        return APR_EINVAL;
    }

    bytes = apr_strtoi64(arg, &end, 10);

    if (end[0]) {
        apr_file_printf(ds->err, "number '%s' is not a number.\n",
                apr_pescape_echo(ds->pool, arg, 1));
        return APR_EINVAL;
    }

    *result = bytes;

    return APR_SUCCESS;
}

/*
 * SQL identifier in regular format. Regular identifiers start with a letter (a-z, but
 * also letters with diacritical marks and non-Latin letters) or an underscore (_).
 * Subsequent characters in an identifier can be letters, underscores, or digits (0-9).
 * The resulting value does not need to be SQL escaped before use.
 */
static apr_status_t device_parse_sql_identifier(device_set_t *ds, device_pair_t *pair,
        const char *arg, const char **translated)
{
    apr_xlate_t* convset;
    apr_status_t status;
    char *out;
    apr_size_t inbytes, outbytes;

    int len = 0;

    if (!arg || !arg[0]) {
        apr_file_printf(ds->err, "argument '%s': is empty.\n",
                apr_pescape_echo(ds->pool, pair->key, 1));
        return APR_INCOMPLETE;
    }

    status = apr_xlate_open(&convset, "UTF-8", APR_LOCALE_CHARSET, ds->pool);
    if (APR_SUCCESS != status) {
        /* could not open xlate, fail */
        apr_file_printf(ds->err, "could not open conversion from current locale: %pm\n",
                &status);
        return status;
    }

    inbytes = strlen(arg);
    outbytes = inbytes * 4 + 1;
    out = apr_palloc(ds->pool, outbytes);

    status = apr_xlate_conv_buffer(convset, arg, &inbytes, out, &outbytes);
    if (APR_SUCCESS != status) {
        /* could not open xlate, fail */
        apr_file_printf(ds->err, "could not convert from current locale: %pm\n",
                &status);
        return status;
    }

    outbytes = strlen(out);

    if (outbytes < pair->q.min) {
        /* not ok */
        apr_file_printf(ds->err,
                "argument '%s': sql identifier is shorter than %"
                APR_INT64_T_FMT " characters.\n",
                apr_pescape_echo(ds->pool, pair->key, 1), pair->q.min);
        return APR_EINVAL;
    }

    if (outbytes > pair->q.max) {
        /* not ok */
        apr_file_printf(ds->err,
                "argument '%s': sql identifier is longer than %"
                APR_INT64_T_FMT " characters.\n",
                apr_pescape_echo(ds->pool, pair->key, 1), pair->q.max);
        return APR_EINVAL;
    }

    while (len < outbytes) {
        char c = out[len++];

        if (c >= '0' && c <= '9') {
            if (len == 1) {
                /* first character cannot be a number */
                apr_file_printf(ds->err, "argument '%s': first character cannot be a number.\n",
                        apr_pescape_echo(ds->pool, pair->key, 1));
                return APR_EINVAL;
            }
            else {
                /* ok */
            }
        }
        else if (c >= 'a' && c <= 'z') {
            /* ok */
        }
        else if (c == '_') {
            /* ok */
        }
        else if (c > 0x7F) {
            /* ok */
        }
        else {
            /* not ok */
            apr_file_printf(ds->err, "argument '%s': '%c' is an invalid character.\n",
                    apr_pescape_echo(ds->pool, pair->key, 1), c);
            return APR_EINVAL;
        }

    }

    if (translated) {
        *translated = out;
    }

    return APR_SUCCESS;
}

/*
 * SQL identifier in delimited format. Delimited identifiers consist of any UTF8 non-zero
 * character. The resulting value must be SQL escaped separately before use.
 */
static apr_status_t device_parse_sql_delimited_identifier(device_set_t *ds, device_pair_t *pair,
        const char *arg, const char **translated)
{
    apr_xlate_t* convset;
    apr_status_t status;
    char *out;
    apr_size_t inbytes, outbytes;

    int len = 0;

    if (!arg || !arg[0]) {
        apr_file_printf(ds->err, "argument '%s': is empty.\n",
                apr_pescape_echo(ds->pool, pair->key, 1));
        return APR_INCOMPLETE;
    }

    status = apr_xlate_open(&convset, "UTF-8", APR_LOCALE_CHARSET, ds->pool);
    if (APR_SUCCESS != status) {
        /* could not open xlate, fail */
        apr_file_printf(ds->err, "could not open conversion from current locale: %pm\n",
                &status);
        return status;
    }

    inbytes = strlen(arg);
    outbytes = inbytes * 4 + 1;
    out = apr_palloc(ds->pool, outbytes);

    status = apr_xlate_conv_buffer(convset, arg, &inbytes, out, &outbytes);
    if (APR_SUCCESS != status) {
        /* could not open xlate, fail */
        apr_file_printf(ds->err, "could not convert from current locale: %pm\n",
                &status);
        return status;
    }

    outbytes = strlen(out);

    if (outbytes < pair->q.min) {
        /* not ok */
        apr_file_printf(ds->err,
                "argument '%s': sql identifier is shorter than %"
                APR_INT64_T_FMT " characters.\n",
                apr_pescape_echo(ds->pool, pair->key, 1), pair->q.min);
        return APR_EINVAL;
    }

    if (outbytes > pair->q.max) {
        /* not ok */
        apr_file_printf(ds->err,
                "argument '%s': sql identifier is longer than %"
                APR_INT64_T_FMT " characters.\n",
                apr_pescape_echo(ds->pool, pair->key, 1), pair->q.max);
        return APR_EINVAL;
    }

    while (len < outbytes) {
        char c = out[len++];

        if (c > 0) {
            /* ok */
        }
        else {
            /* not ok */
            apr_file_printf(ds->err, "argument '%s': '%c' is an invalid character.\n",
                    apr_pescape_echo(ds->pool, pair->key, 1), c);
            return APR_EINVAL;
        }

    }

    if (translated) {
        *translated = out;
    }

    return APR_SUCCESS;
}

/**
 * User is a string which must match one of a series of existing users,
 * potentially limited to one or more groups.
 */
static apr_status_t device_parse_user(device_set_t *ds, device_pair_t *pair,
        const char *arg, apr_array_header_t *options, const char **option)
{
    const char *none = NULL;
    apr_status_t status;
    apr_size_t arglen = arg ? strlen(arg) : 0;

    apr_array_header_t *possibles = apr_array_make(ds->pool, 10, sizeof(char *));

    int i, j;

    int exact = 0;

    if (option) {
        option[0] = NULL; /* until further notice */
    }

    if (pair->optional == DEVICE_OPTIONAL) {
        none = DEVICE_SELECT_NONE;
    }

    if (!pair->u.groups) {

        struct passwd *pwd;

        setpwent();

        do {

            const char *user;
            const char **possible;

            if (none) {

                user = none;

            } else {

                apr_set_os_error(0);
                pwd = getpwent();
                status = apr_get_os_error();

                if (APR_SUCCESS != status) {
                    apr_file_printf(ds->err, "cannot read users '%s': %pm\n", pair->key,
                            &status);
                    break;
                }

                if (!pwd) {
                    break;
                }

                user = pwd->pw_name;
            }

            possible = apr_array_push(possibles);
            possible[0] = apr_pstrdup(ds->pool, user);

            exact = (0 == strcmp(arg, user));

            if (!strncmp(arg, user, arglen)) {

                const char **opt;

                if (exact) {
                    apr_array_clear(options);
                }

                opt = apr_array_push(options);
                opt[0] = apr_pstrcat(ds->pool,
                        pair->optional == DEVICE_OPTIONAL ? "-" : "*",
                        device_pescape_shell(ds->pool, pair->key), "=",
                        device_pescape_shell(ds->pool, user),
                        NULL);

                if (option) {
                    if (none) {
                        option[0] = NULL;
                    }
                    else {
                        option[0] = possible[0];
                    }
                }
            }

            if (exact) {
                /* exact matches short circuit */
                break;
            }

            none = NULL;

        } while (1);

        endpwent();

    }
    else {

        for (i = 0; i < pair->u.groups->nelts; i++) {

            struct group *gr;

            const char *group = APR_ARRAY_IDX(pair->u.groups, i, const char *);

            apr_set_os_error(0);
            gr = getgrnam(group);
            status = apr_get_os_error();

            if (APR_SUCCESS != status) {
                apr_file_printf(ds->err, "cannot read groups '%s': %pm\n", pair->key,
                        &status);
            }
            else if (gr && gr->gr_mem) {

                j = 0;

                do {

                    const char *user;
                    const char **possible;

                    if (none) {
                        user = none;
                    } else {
                        user = gr->gr_mem[j++];
                    }

                    if (!user) {
                        break;
                    }

                    possible = apr_array_push(possibles);
                    possible[0] = apr_pstrdup(ds->pool, user);

                    exact = (0 == strcmp(arg, user));

                    if (!strncmp(arg, user, arglen)) {

                        const char **opt;

                        if (exact) {
                            apr_array_clear(options);
                        }

                        opt = apr_array_push(options);
                        opt[0] = apr_pstrcat(ds->pool,
                                pair->optional == DEVICE_OPTIONAL ? "-" : "*",
                                device_pescape_shell(ds->pool, pair->key), "=",
                                device_pescape_shell(ds->pool, user),
                                NULL);

                        if (option) {
                            if (none) {
                                option[0] = NULL;
                            }
                            else {
                                option[0] = possible[0];
                            }
                        }
                    }

                    if (exact) {
                        /* exact matches short circuit */
                        break;
                    }

                    none = NULL;

                } while (1);

            }

            endgrent();

            if (exact) {
                /* exact matches short circuit */
                break;
            }

        }

    }


    if (option && option[0]) {
        if (options->nelts == 1) {
            /* all ok */
        }
        else {
            device_error_possibles(ds, pair->key, possibles);
            return APR_INCOMPLETE;
        }
    }

    return status;
}

enum dn_state {
    DN_DN_START,
    DN_RDN_START,
    DN_ATAV_START,
    DN_AT_START,
    DN_DESCR,
    DN_NUMERICOID_N_START,
    DN_NUMERICOID_N,
    DN_V_START,
    DN_HEX_START,
    DN_HEX_LEFT,
    DN_HEX_RIGHT,
    DN_STRING_START,
    DN_STRING,
    DN_STRING_ESC,
    DN_STRING_HEX,
};

/**
 * Distinguished name is a string described by RFC4514, containing a series
 * of name value pairs.
 */
static apr_status_t device_parse_distinguished_name(device_set_t *ds, device_pair_t *pair,
        const char *arg, apr_array_header_t *options, const char **option)
{
    apr_size_t arglen = arg ? strlen(arg) : 0;

//    apr_array_header_t *possibles = apr_array_make(ds->pool, 10, sizeof(char *));

    const char *cp;

    enum dn_state state = DN_DN_START;

    char ch = 0, prev;

    if (option) {
        option[0] = NULL; /* until further notice */
    }

    if (pair->optional == DEVICE_REQUIRED && !arglen) {
        apr_file_printf(ds->err, "'%s' is required\n", pair->key);
        return APR_EGENERAL;
    }

    cp = arg;

    while (*cp) {

        prev = ch;
        ch = *cp;

        switch (state) {
        case DN_DN_START:
            if (ch == ',') {
                apr_file_printf(ds->err, "'%s' has a stray '%c'\n", pair->key, ch);
                return APR_EINVAL;
            }

            state = DN_RDN_START;
            continue;
        case DN_RDN_START:
            if (ch == '+') {
                apr_file_printf(ds->err, "'%s' has a stray '%c'\n", pair->key, ch);
                return APR_EINVAL;
            }

            state = DN_ATAV_START;
            continue;
        case DN_ATAV_START:

            state = DN_AT_START;
            continue;
        case DN_AT_START:
            /* keystring = leadkeychar *keychar
             * leadkeychar = ALPHA
             * keychar = ALPHA / DIGIT / HYPHEN
             * descr = keystring
             * numericoid = number 1*( DOT number )
             * oid = descr / numericoid
             */
            if (ch == '=') {
                apr_file_printf(ds->err, "'%s' attribute type is empty\n", pair->key);
                return APR_EINVAL;
            }
            else if (apr_isalpha(ch)) {
                state = DN_DESCR;
                continue;
            }
            else if (apr_isdigit(ch)) {
                state = DN_NUMERICOID_N_START;
                continue;
            }

            apr_file_printf(ds->err, "'%s' attribute type character %c is not alphanumeric\n", pair->key, ch);
            return APR_EINVAL;

        case DN_DESCR:
            /* keystring = leadkeychar *keychar
             * leadkeychar = ALPHA
             * keychar = ALPHA / DIGIT / HYPHEN
             * descr = keystring
             */
            if (ch == '=') {
                state = DN_V_START;
                cp++;
                continue;
            }
            else if (ch != '-' && !apr_isalnum(ch)) {
                apr_file_printf(ds->err, "'%s' attribute type character %c is not alphanumeric/hyphen\n", pair->key, ch);
                return APR_EINVAL;
            }

            break;
        case DN_NUMERICOID_N_START:
            /* numericoid = number 1*( DOT number )
             */
            if (!apr_isdigit(ch)) {
                apr_file_printf(ds->err, "'%s' attribute type character %c is not numeric\n", pair->key, ch);
                return APR_EINVAL;
            }

            state = DN_NUMERICOID_N;
            cp++;
            continue;
        case DN_NUMERICOID_N:
            /* numericoid = number 1*( DOT number )
             */
            if (ch == '=') {
                state = DN_V_START;
                cp++;
                continue;
            }
            if (ch == '.') {
                state = DN_NUMERICOID_N_START;
                cp++;
                continue;
            }
            if (!apr_isdigit(ch)) {
                apr_file_printf(ds->err, "'%s' attribute type character %c is not numeric\n", pair->key, ch);
                return APR_EINVAL;
            }

            break;
        case DN_V_START:
            /* attributeValue = string / hexstring
             * hexstring = SHARP 1*hexpair
             * hexpair = HEX HEX
             */
            if (ch == ',' || ch == '+') {
                state = DN_RDN_START;
                cp++;
                continue;
            }
            else if (ch == '#') {
                state = DN_HEX_START;
                cp++;
                continue;
            }

            state = DN_STRING_START;
            continue;

        case DN_HEX_START:
            /* attributeValue = string / hexstring
             * hexstring = SHARP 1*hexpair
             * hexpair = HEX HEX
             */
            if (!apr_isxdigit(ch)) {
                apr_file_printf(ds->err, "'%s' attribute type character %c is not a hex digit\n", pair->key, ch);
                return APR_EINVAL;
            }

            state = DN_HEX_RIGHT;
            cp++;
            continue;

        case DN_HEX_LEFT:
            /* attributeValue = string / hexstring
             * hexstring = SHARP 1*hexpair
             * hexpair = HEX HEX
             */
            if (ch == ',' || ch == '+') {
                state = DN_RDN_START;
                cp++;
                continue;
            }
            else if (!apr_isxdigit(ch)) {
                apr_file_printf(ds->err, "'%s' attribute type character %c is not a hex digit\n", pair->key, ch);
                return APR_EINVAL;
            }

            state = DN_HEX_RIGHT;
            cp++;
            continue;

        case DN_HEX_RIGHT:
            /* attributeValue = string / hexstring
             * hexstring = SHARP 1*hexpair
             * hexpair = HEX HEX
             */
            if (!apr_isxdigit(ch)) {
                apr_file_printf(ds->err, "'%s' attribute type character %c is not a hex digit\n", pair->key, ch);
                return APR_EINVAL;
            }

            state = DN_HEX_LEFT;
            cp++;
            continue;

        case DN_STRING_START:
            /* ; The following characters are to be escaped when they appear
             * ; in the value to be encoded: ESC, one of <escaped>, leading
             * ; SHARP or SPACE, trailing SPACE, and NULL.
             * string =   [ ( leadchar / pair ) [ *( stringchar / pair )
             *            ( trailchar / pair ) ] ]
             *
             * leadchar = LUTF1 / UTFMB
             * LUTF1 = %x01-1F / %x21 / %x24-2A / %x2D-3A /
             *         %x3D / %x3F-5B / %x5D-7F
             *
             * trailchar  = TUTF1 / UTFMB
             * TUTF1 = %x01-1F / %x21 / %x23-2A / %x2D-3A /
             *         %x3D / %x3F-5B / %x5D-7F
             *
             * stringchar = SUTF1 / UTFMB
             * SUTF1 = %x01-21 / %x23-2A / %x2D-3A /
             *         %x3D / %x3F-5B / %x5D-7F
             *
             * pair = ESC ( ESC / special / hexpair )
             * special = escaped / SPACE / SHARP / EQUALS
             * escaped = DQUOTE / PLUS / COMMA / SEMI / LANGLE / RANGLE
             */

            /* leadchar: has no [space]"#,+;<>\
             * stringchar: has no ",+;<>\
             * trailchar: has no [space]",+;<>\
             */

            /* %x20 */
            if (ch == ' ') {
                apr_file_printf(ds->err, "'%s' value cannot start with a space\n", pair->key);
                return APR_EINVAL;
            }

            state = DN_STRING;
            continue;

        case DN_STRING:

               /* stringchar: has no ",+;<>\ */

            if (ch == '"' || ch == ';' || ch == '<' || ch == '>') {
                apr_file_printf(ds->err, "'%s' value character %c is not escaped\n", pair->key, ch);
                return APR_EINVAL;
            }

            /* %x2B %x2C */
            else if (ch == ',' || ch == '+') {

                if (prev == ' ') {
                    apr_file_printf(ds->err, "'%s' value cannot end with a space\n", pair->key);
                    return APR_EINVAL;
                }

                state = DN_RDN_START;
                cp++;
                continue;
            }

            else if (ch == '\\') {
                state = DN_STRING_ESC;
                cp++;
                continue;
            }

            break;

        case DN_STRING_ESC:
            /*
             * pair = ESC ( ESC / special / hexpair )
             * special = escaped / SPACE / SHARP / EQUALS
             * escaped = DQUOTE / PLUS / COMMA / SEMI / LANGLE / RANGLE
             */

            switch (ch) {
            case '\\':
            case '"':
            case '+':
            case ',':
            case ';':
            case '<':
            case '>':
            case ' ':
            case '#':
            case '=':
                /* ESC / special */

                state = DN_STRING;
                cp++;
                ch = 0; /* previous character is always fine */
                continue;

            default:

                if (apr_isxdigit(ch)) {
                    state = DN_STRING_HEX;
                    cp++;
                    continue;
                }
            }

            apr_file_printf(ds->err, "'%s' value character %c is not a valid escape character (\\\"+,;<> #=[hex])\n", pair->key, ch);
            return APR_EINVAL;

        case DN_STRING_HEX:

            if (apr_isxdigit(ch)) {
                state = DN_STRING;
                cp++;
                continue;
            }

            apr_file_printf(ds->err, "'%s' value character %c is not a valid escape hex character\n", pair->key, ch);
            return APR_EINVAL;
        }

        cp++;
    }

    switch (state) {
    case DN_V_START:
    case DN_HEX_LEFT:
    case DN_STRING:
    case DN_STRING_START:
        /* if we're parsing the last string, it's valid to be done */

        if (ch == ' ') {
            apr_file_printf(ds->err, "'%s' value cannot end with a space\n", pair->key);
            return APR_EINVAL;
        }

        return APR_SUCCESS;

    case DN_HEX_START:
    case DN_HEX_RIGHT:
    case DN_STRING_HEX:

        apr_file_printf(ds->err, "'%s' ends too early (expecting hex digit)\n", pair->key);
        return APR_EINVAL;

    case DN_RDN_START:

        apr_file_printf(ds->err, "'%s' ends too early (expecting relative distinguished name)\n", pair->key);
        return APR_EINVAL;

    case DN_STRING_ESC:

        apr_file_printf(ds->err, "'%s' ends too early (expecting escape)\n", pair->key);
        return APR_EINVAL;

    case DN_DESCR:
    case DN_NUMERICOID_N:

        apr_file_printf(ds->err, "'%s' ends too early (attribute needs value)\n", pair->key);
        return APR_EINVAL;

    case DN_DN_START:
    case DN_ATAV_START:
    case DN_AT_START:
    case DN_NUMERICOID_N_START:

        apr_file_printf(ds->err, "'%s' ends too early %d\n", pair->key, state);
        return APR_EINVAL;

    }

}

static char *trim(char *buffer) {

    char *start = buffer, *end;

    while(*buffer && apr_isspace(*buffer)) {
        start = buffer++;
    }

    end = start;

    while(*buffer) {
        if (!apr_isspace(*buffer)) {
            end = ++buffer;
        }
        else {
            buffer++;
        }
    }

    *end = 0;

    return start;
}

static apr_status_t device_get(device_set_t *ds, const char *arg,
        apr_array_header_t *options, const char **option, const char **path,
        int *exact)
{

    apr_dir_t *thedir;
    apr_finfo_t dirent;

    apr_array_header_t *possibles = apr_array_make(ds->pool, 10, sizeof(char *));

    apr_status_t status;

    apr_size_t arglen = strlen(arg);

    device_pair_t *pair;

    pair = apr_hash_get(ds->pairs, ds->key, APR_HASH_KEY_STRING);

    if (!pair) {
        apr_file_printf(ds->err, "key '%s' is not recognised.\n",
                apr_pescape_echo(ds->pool, ds->key, 1));
        return APR_EINVAL;
    }

    /* scan the directories to find a match */
    if ((status = apr_dir_open(&thedir, ".", ds->pool)) != APR_SUCCESS) {
        /* could not open directory, fail */
        apr_file_printf(ds->err, "could not open current directory: %pm\n", &status);
        return status;
    }

    do {
        const char **possible;

        status = apr_dir_read(&dirent,
                APR_FINFO_TYPE | APR_FINFO_NAME | APR_FINFO_WPROT, thedir);
        if (APR_STATUS_IS_INCOMPLETE(status)) {
            continue; /* ignore un-stat()able files */
        } else if (status != APR_SUCCESS) {
            break;
        }

        /* hidden files are ignored */
        if (dirent.name[0] == '.') {
            continue;
        }

        switch (dirent.filetype) {
        case APR_DIR: {

            apr_pool_t *pool;
            char *name;
            apr_file_t *in;
            const char *keyname;
            char *keypath;
            apr_off_t end = 0, start = 0;

            apr_pool_create(&pool, ds->pool);

            keyname = apr_pstrcat(pool, pair->key, pair->suffix, NULL);
            if (APR_SUCCESS
                    != (status = apr_filepath_merge(&keypath, dirent.name,
                            keyname, APR_FILEPATH_NOTABSOLUTE, pool))) {
                apr_file_printf(ds->err, "cannot merge option set key '%s': %pm\n", pair->key,
                        &status);
            }

            /* open the key */
            else if (APR_SUCCESS
                    != (status = apr_file_open(&in, keypath, APR_FOPEN_READ,
                            APR_FPROT_OS_DEFAULT, pool))) {
                apr_file_printf(ds->err, "cannot open option set '%s': %pm\n", pair->key,
                        &status);
            }

            /* how long is the key? */
            else if (APR_SUCCESS
                    != (status = apr_file_seek(in, APR_END, &end))) {
                apr_file_printf(ds->err, "cannot seek end of option set '%s': %pm\n", pair->key,
                        &status);
            }

            /* back to the beginning */
            else if (APR_SUCCESS
                    != (status = apr_file_seek(in, APR_SET, &start))) {
                apr_file_printf(ds->err, "cannot seek end of option set '%s': %pm\n", pair->key,
                        &status);
            }

            else {
                int size = end + 1;
                name = apr_palloc(pool, size);

                status = apr_file_gets(name, size, in);

                if (APR_EOF == status) {
                    status = APR_SUCCESS;
                }
                if (APR_SUCCESS == status) {
                    /* short circuit, all good */
                    name = trim(name);
                }
                else {
                    apr_file_printf(ds->err, "cannot read option set '%s': %pm\n", pair->key,
                            &status);
                }
            }

            if (status != APR_SUCCESS) {
                apr_pool_destroy(pool);
                break;
            }

            int ex = (0 == strcmp(arg, name));

            possible = apr_array_push(possibles);
            *possible = apr_pstrdup(ds->pool, name);

            if (!strncmp(arg, name, arglen)) {

                const char **opt;

                if (ex) {
                    apr_array_clear(options);
                }

                opt = apr_array_push(options);
                opt[0] = apr_pstrcat(ds->pool, "*",
                        device_pescape_shell(ds->pool, name), " ",
                        NULL);

                if (option) {
                    *option = *possible;
                }
                if (path) {
                    *path = apr_pstrdup(ds->pool, dirent.name);
                }
                if (exact) {
                    *exact = ex;
                }
            }

            apr_pool_destroy(pool);

            if (ex) {
                /* exact matches short circuit */
                goto done;
            }

            break;
        }
        default:
            break;
        }

    } while (1);

done:

    apr_dir_close(thedir);

    if (APR_SUCCESS == status) {
        /* short circuit, all good */
    }
    else if (APR_STATUS_IS_ENOENT(status)) {

        if (option) {
            if (options->nelts == 1) {
                /* all ok */
            }
            else {
                device_error_possibles(ds, arg, possibles);

                return APR_INCOMPLETE;
            }
        }

        status = APR_SUCCESS;
    }
    else {
        apr_file_printf(ds->err, "cannot read option '%s': %pm\n",
                apr_pescape_echo(ds->pool, arg, 1), &status);
    }

    return APR_SUCCESS;
}

static apr_status_t device_files(device_set_t *ds, apr_array_header_t *files)
{
    apr_file_t *out;

    char *pwd;
    const char *key = NULL, *keypath = NULL, *keyval = NULL;
    apr_status_t status = APR_SUCCESS;
    int i;

    /* save the present working directory */
    status = apr_filepath_get(&pwd, APR_FILEPATH_NATIVE, ds->pool);

    if (APR_SUCCESS != status) {
        apr_file_printf(ds->err, "cannot access cwd: %pm\n", &status);
        return status;
    }

    if (ds->mode == DEVICE_ADD) {

        apr_hash_index_t *hi;
        void *v;
        device_pair_t *pair;

        /* check for required options that remain unset */

        for (hi = apr_hash_first(ds->pool, ds->pairs); hi; hi = apr_hash_next(hi)) {

            apr_hash_this(hi, NULL, NULL, &v);
            pair = v;

            if (pair->optional == DEVICE_REQUIRED) {

                int found = 0;

                for (i = 0; i < files->nelts; i++)
                {
                    device_file_t *file = &APR_ARRAY_IDX(files, i, device_file_t);

                    if (!strcmp(pair->key, file->key)) {
                        found = 1;
                        break;
                    }
                }

                if (!found) {
                    apr_file_printf(ds->err, "'%s' is required.\n",
                            apr_pescape_echo(ds->pool, pair->key, 1));
                    return APR_EINVAL;
                }
            }

        }

        /* try the directory create */
        if (ds->key) {

            apr_uuid_t uuid;
            char ustr[APR_UUID_FORMATTED_LENGTH + 1];

            /* test for uniqueness */

            apr_uuid_get(&uuid);
            apr_uuid_format(ustr, &uuid);

            keypath = ustr;

            if (APR_SUCCESS != (status = apr_dir_make(keypath,
                    APR_FPROT_OS_DEFAULT, ds->pool))) {
                apr_file_printf(ds->err, "cannot create '%s': %pm\n", ds->key, &status);
                return status;
            }

            /* change current working directory */
            status = apr_filepath_set(ustr, ds->pool);
            if (APR_SUCCESS != status) {
                apr_file_printf(ds->err, "cannot access '%s' (chdir): %pm\n", ds->key, &status);
                return status;
            }
            else if (APR_SUCCESS
                != (status = apr_file_open(&out, DEVICE_ADD_MARKER, APR_FOPEN_CREATE | APR_FOPEN_WRITE,
                    APR_FPROT_OS_DEFAULT, ds->pool))) {
                apr_file_printf(ds->err, "cannot create add mark '%s': %pm\n", keyval,
                    &status);
                return status;
            }
            else if (APR_SUCCESS != (status = apr_file_close(out))) {
                apr_file_printf(ds->err, "cannot close add mark '%s': %pm\n", keyval, &status);
                return status;
            }
            else if (APR_SUCCESS
                    != (status = apr_file_perms_set(DEVICE_ADD_MARKER,
                            APR_FPROT_OS_DEFAULT & ~DEVICE_FILE_UMASK))) {
                apr_file_printf(ds->err, "cannot set permissions to add mark '%s': %pm\n",
                        keyval, &status);
                return status;
            }

        }
        else {
            apr_file_printf(ds->err, "option '%s' does not exist\n", ds->key);
            return status;
        }

    }
    else {

        if (ds->key) {

            /* re-index and implement ordering here */


            /* change current working directory */
            status = apr_filepath_set(ds->keypath, ds->pool);

            if (APR_SUCCESS != status) {
                apr_file_printf(ds->err, "cannot access '%s': %pm\n", ds->key, &status);
                return status;
            }

        }

        /* try to mark updated file */
        if (APR_SUCCESS
                != (status = apr_file_open(&out, DEVICE_SET_MARKER,
                        APR_FOPEN_CREATE | APR_FOPEN_WRITE,
                        APR_FPROT_OS_DEFAULT, ds->pool))) {
            apr_file_printf(ds->err, "cannot create set mark '%s': %pm\n", keyval,
                    &status);
            return status;
        } else if (APR_SUCCESS != (status = apr_file_close(out))) {
            apr_file_printf(ds->err, "cannot close set mark '%s': %pm\n", keyval,
                    &status);
            return status;
        } else if (APR_SUCCESS != (status = apr_file_perms_set(DEVICE_SET_MARKER,
                APR_FPROT_OS_DEFAULT & ~DEVICE_FILE_UMASK))) {
            apr_file_printf(ds->err, "cannot set permissions to set mark '%s': %pm\n",
                    keyval, &status);
            return status;
        }

    }

    /* try to write */
    for (i = 0; i < files->nelts; i++)
    {
        apr_file_t *out;

        device_file_t *file = &APR_ARRAY_IDX(files, i, device_file_t);

        /* move away the original */
        file->backup = apr_psprintf(ds->pool, "%s.backup", file->dest);
        if (APR_SUCCESS
                != (status = apr_file_rename(file->dest, file->backup, ds->pool))
                && !APR_STATUS_IS_ENOENT(status)) {
            apr_file_printf(ds->err, "cannot move '%s': %pm\n", file->key, &status);
            break;
        }

        if (!file->val) {

            /* no value, write nothing */

        }
        else if (file->type == APR_REG) {

            /* write the result */
            if (APR_SUCCESS
                    != (status = apr_file_mktemp(&out, file->template,
                            APR_FOPEN_CREATE | APR_FOPEN_WRITE | APR_FOPEN_EXCL,
                            ds->pool))) {
                apr_file_printf(ds->err, "cannot save '%s': %pm\n", file->key, &status);
                break;
            }
            else if (APR_SUCCESS
                    != (status = apr_file_write_full(out, file->val, strlen(file->val),
                            NULL))) {
                apr_file_printf(ds->err, "cannot write '%s': %pm\n", file->key, &status);
                break;
            }
            else if (APR_SUCCESS != (status = apr_file_close(out))) {
                apr_file_printf(ds->err, "cannot close '%s': %pm\n", file->key, &status);
                break;
            }
            else if (APR_SUCCESS
                    != (status = apr_file_perms_set(file->template,
                            APR_FPROT_OS_DEFAULT & ~DEVICE_FILE_UMASK))) {
                apr_file_printf(ds->err, "cannot set permissions on '%s': %pm\n",
                        file->key, &status);
                break;
            }
        }
        else if (file->type == APR_LNK) {

            /* APR needs a mktemp function that can do symlinks */
            pid_t pid = getpid();
            file->template = apr_psprintf(ds->pool, "%s;%" APR_PID_T_FMT, file->dest, pid);

            errno = 0;
            symlink(file->val, file->template);
            if (APR_SUCCESS != (status = errno)) {
                apr_file_printf(ds->err, "cannot link '%s': %pm\n", file->key, &status);
                break;
            }
        }

        if (file->index == DEVICE_INDEXED) {
            keyval = file->val;
        }

    }

    /* could not write, try to rollback */
    if (APR_SUCCESS != status && !APR_STATUS_IS_ENOENT(status)) {

        for (i = 0; i < files->nelts; i++) {

            apr_status_t status; /* intentional shadowing of status */

            device_file_t *file = &APR_ARRAY_IDX(files, i, device_file_t);

            if (file->backup && APR_SUCCESS
                    != (status = apr_file_rename(file->backup, file->dest, ds->pool))
                    && !APR_STATUS_IS_ENOENT(status)) {
                apr_file_printf(ds->err, "cannot move '%s': %pm\n", file->key, &status);
            }

            if (APR_SUCCESS != (status = apr_file_remove(file->template, ds->pool))
                    && !APR_STATUS_IS_ENOENT(status)) {
                apr_file_printf(ds->err, "cannot remove '%s': %pm\n", file->key, &status);
            }

        }

        /* remove the updated file here */
        if (ds->mode != DEVICE_ADD && APR_SUCCESS !=
                (status = apr_file_remove(DEVICE_SET_MARKER, ds->pool))
                && !APR_STATUS_IS_ENOENT(status)) {
            apr_file_printf(ds->err, "cannot remove set mark: %pm\n", &status);
        }

        if (ds->key) {

            /* revert to present working directory */
            status = apr_filepath_set(pwd, ds->pool);
            if (APR_SUCCESS != status) {
                apr_file_printf(ds->err, "cannot revert '%s': %pm\n", key, &status);
                return status;
            }

            if (ds->mode == DEVICE_ADD) {
                if (APR_SUCCESS != (status = apr_dir_remove(keypath, ds->pool))) {
                    apr_file_printf(ds->err, "cannot remove '%s': %pm\n", key, &status);
                    return status;
                }
            }
            else {

                /* implement the undo of the reindex here */

            }
        }

        return status;
    }

    /* otherwise do the renames */
    else {

        for (i = 0; i < files->nelts; i++) {

            device_file_t *file = &APR_ARRAY_IDX(files, i, device_file_t);

            if (APR_SUCCESS != (status = apr_file_rename(file->template, file->dest, ds->pool))
                    && !APR_STATUS_IS_ENOENT(status)) {
                apr_file_printf(ds->err, "cannot move '%s': %pm\n", file->key, &status);
            }

            if (file->backup && APR_SUCCESS != (status = apr_file_remove(file->backup, ds->pool))
                    && !APR_STATUS_IS_ENOENT(status)) {
                apr_file_printf(ds->err, "cannot remove '%s': %pm\n", file->key, &status);
            }

        }

        /* revert to present working directory */
        status = apr_filepath_set(pwd, ds->pool);
        if (APR_SUCCESS != status) {
            apr_file_printf(ds->err, "cannot create index (cwd): %pm\n", &status);
            return status;
        }

        /* too late to back out */
        if (ds->keyval && keyval) {
            apr_file_rename(ds->keyval, keyval, ds->pool);
        }

        else if (keypath && keyval) {
            symlink(keypath, keyval);
        }

        return APR_SUCCESS;
    }

}

static apr_status_t device_complete(device_set_t *ds, const char **args)
{
    const char *key = NULL, *value = NULL;

    apr_status_t status;
    int count = 0;

    if (!args[0]) {
        /* no args is not ok */
        apr_file_printf(ds->err, "complete needs one or more arguments.\n");
        return APR_EINVAL;
    }

    if (ds->key && ds->mode == DEVICE_SET) {

        apr_array_header_t *options = apr_array_make(ds->pool, 10, sizeof(char *));
        int i;

        if (!args[1]) {
            status = device_get(ds, args[0], options, NULL, NULL, NULL);

            /* complete on the ids */
            for (i = 0; i < options->nelts; i++) {
                const char *option = APR_ARRAY_IDX(options, i, const char *);
                apr_file_printf(ds->out, "%s\n", option);
            }

            return status;
        }
        else {
            status = device_get(ds, args[0], options, &ds->key, &ds->keypath, NULL);

            if (APR_SUCCESS != status) {
                return status;
            }
        }

        count = 2;
    }

    /* find the last key/value pair, or just the key if odd */
    while(args[count]) {
        if (!args[count + 1]) {
            key = args[count + 0];
            value = NULL;
            break;
        }
        else {
            key = args[count + 0];
            value = args[count + 1];
        }
        count += 2;
    }

    if (ds->mode == DEVICE_REMOVE) {
        if (value) {
            /* more than one arg is not ok */
            apr_file_printf(ds->err, "complete has more than one argument.\n");
            return APR_EINVAL;
        }
        else {

            apr_array_header_t *options = apr_array_make(ds->pool, 10, sizeof(char *));
            int i;

            status = device_get(ds, args[0], options, NULL, NULL, NULL);

            /* complete on the keys */
            for (i = 0; i < options->nelts; i++) {
                const char *option = APR_ARRAY_IDX(options, i, const char *);
                apr_file_printf(ds->out, "%s\n", option);
            }

            return status;
        }
    }
    else if (value) {

        device_pair_t *pair;

        pair = apr_hash_get(ds->pairs, key, APR_HASH_KEY_STRING);

        if (pair) {

            apr_array_header_t *options = apr_array_make(ds->pool, 10, sizeof(char *));
            int i;

            switch (pair->type) {
            case DEVICE_PAIR_INDEX:
                status = device_parse_index(ds, pair, value, NULL);
                break;
            case DEVICE_PAIR_PORT:
                status = device_parse_port(ds, pair, value);
                break;
            case DEVICE_PAIR_UNPRIVILEGED_PORT:
                status = device_parse_unprivileged_port(ds, pair, value);
                break;
            case DEVICE_PAIR_HOSTNAME:
                status = device_parse_hostname(ds, pair, value);
                break;
            case DEVICE_PAIR_FQDN:
                status = device_parse_fqdn(ds, pair, value);
                break;
            case DEVICE_PAIR_SELECT:
                status = device_parse_select(ds, pair, value, options, NULL);
                break;
            case DEVICE_PAIR_BYTES:
                status = device_parse_bytes(ds, pair, value, options, NULL);
                break;
            case DEVICE_PAIR_SYMLINK:
                status = device_parse_symlink(ds, pair, value, options, NULL);
                break;
            case DEVICE_PAIR_SQL_IDENTIFIER:
                status = device_parse_sql_identifier(ds, pair, value, NULL);
                break;
            case DEVICE_PAIR_SQL_DELIMITED_IDENTIFIER:
                status = device_parse_sql_delimited_identifier(ds, pair, value,
                        NULL);
                break;
            case DEVICE_PAIR_USER:
                status = device_parse_user(ds, pair, value, options, NULL);
                break;
            case DEVICE_PAIR_DISTINGUISHED_NAME:
                status = device_parse_distinguished_name(ds, pair, value, options, NULL);
                break;
            default:
                status = APR_EINVAL;
            }

            for (i = 0; i < options->nelts; i++) {
                const char *option = APR_ARRAY_IDX(options, i, const char *);
                apr_file_printf(ds->out, "%s\n", option);
            }

        }
        else {
            // FIXME: add option for an "overflow" of unknown arguments
            apr_file_printf(ds->err, "key '%s' is not recognised.\n",
                    apr_pescape_echo(ds->pool, key, 1));
            return APR_EINVAL;
        }

    }
    else {

        apr_hash_index_t *hi;
        void *v;
        device_pair_t *pair;

        for (hi = apr_hash_first(ds->pool, ds->pairs); hi; hi = apr_hash_next(hi)) {

            apr_hash_this(hi, NULL, NULL, &v);
            pair = v;

            if (!key || !key[0] || !strncmp(key, pair->key, strlen(key))) {
                apr_file_printf(ds->out, "%c%s=\n",
                        pair->optional == DEVICE_OPTIONAL ? '-' : '*',
                        device_pescape_shell(ds->pool, pair->key));
            }

        }

        status = APR_INCOMPLETE;

    }

    return status;
}

static apr_status_t device_parse(device_set_t *ds, const char *key, const char *val, apr_array_header_t *files)
{
    device_file_t *file;
    device_pair_t *pair;

    apr_status_t status;

    /* look up the parameter */
    pair = apr_hash_get(ds->pairs, key, APR_HASH_KEY_STRING);

    if (pair) {

        apr_array_header_t *options = apr_array_make(ds->pool, (10), sizeof(char *));

        file = apr_array_push(files);
        file->type = APR_REG;

        switch (pair->type) {
        case DEVICE_PAIR_INDEX:
            status = device_parse_index(ds, pair, val, &val);
            break;
        case DEVICE_PAIR_PORT:
            status = device_parse_port(ds, pair, val);
            break;
        case DEVICE_PAIR_UNPRIVILEGED_PORT:
            status = device_parse_unprivileged_port(ds, pair, val);
            break;
        case DEVICE_PAIR_HOSTNAME:
            status = device_parse_hostname(ds, pair, val);
            break;
        case DEVICE_PAIR_FQDN:
            status = device_parse_fqdn(ds, pair, val);
            break;
        case DEVICE_PAIR_SELECT:
            status = device_parse_select(ds, pair, val, options, &val);
            break;
        case DEVICE_PAIR_BYTES:
            status = device_parse_bytes(ds, pair, val, options, &val);
            break;
        case DEVICE_PAIR_SYMLINK:
            status = device_parse_symlink(ds, pair, val, options, &val);
            file->type = APR_LNK;
            break;
        case DEVICE_PAIR_SQL_IDENTIFIER:
            status = device_parse_sql_identifier(ds, pair, val, &val);
            break;
        case DEVICE_PAIR_SQL_DELIMITED_IDENTIFIER:
            status = device_parse_sql_delimited_identifier(ds, pair, val,
                    &val);
            break;
        case DEVICE_PAIR_USER:
            status = device_parse_user(ds, pair, val, options, &val);
            break;
        case DEVICE_PAIR_DISTINGUISHED_NAME:
            status = device_parse_distinguished_name(ds, pair, val, options, &val);
            break;
        }

        file->dest = apr_pstrcat(ds->pool, pair->key, pair->suffix, NULL);
        file->template = apr_pstrcat(ds->pool, file->dest, ".XXXXXX", NULL);
        file->key = key;
        file->val = val;
        file->index = pair->index;

        if (APR_SUCCESS != status) {
            return status;
        }

        if (ds->key && !strcmp(ds->key, key)) {

            /* index must be unique */

            int exact = 0;

            apr_array_header_t *options = apr_array_make(ds->pool, 10, sizeof(char *));

            status = device_get(ds, val, options, NULL, NULL, &exact);

            if (APR_SUCCESS != status) {
                return status;
            }

            if (exact) {
                apr_file_printf(ds->err, "%s already exists.\n", ds->key);
                return APR_EINVAL;
            }

        }

        if (pair->optional == DEVICE_REQUIRED && !file->val) {
            apr_file_printf(ds->err, "'%s' is required, and cannot be unset.\n",
                    apr_pescape_echo(ds->pool, key, 1));
            return APR_EINVAL;
        }

    }
    else {
        // FIXME: add option for an "overflow" of unknown arguments
        apr_file_printf(ds->err, "argument '%s' is not recognised.\n",
                apr_pescape_echo(ds->pool, key, 1));
        return APR_EINVAL;
    }

    return status;
}

static apr_status_t device_add(device_set_t *ds, const char **args)
{
    const char *key = NULL, *val = NULL;
    apr_status_t status = APR_SUCCESS;
    int len;

    for (len = 0; args && args[len]; len++);

    apr_array_header_t *files = apr_array_make(ds->pool, len, sizeof(device_file_t));

    while (args && *args) {

        const char *arg = *(args++);

        if (!key) {
            key = arg;
            continue;
        }
        else {
            val = arg;
        }

        status = device_parse(ds, key, val, files);

        if (APR_SUCCESS != status) {
            break;
        }

        key = NULL;
        val = NULL;
    }

    if (key && !val) {
        apr_file_printf(ds->err, "argument '%s' has no corresponding value.\n",
                apr_pescape_echo(ds->pool, key, 1));
        return APR_EINVAL;
    }

    if (APR_SUCCESS == status) {
        status = device_files(ds, files);
    }

    return status;
}

static apr_status_t device_set(device_set_t *ds, const char **args)
{
    const char *key = NULL, *val = NULL;
    apr_status_t status = APR_SUCCESS;
    int len;

    for (len = 0; args && args[len]; len++);

    apr_array_header_t *files = apr_array_make(ds->pool, len, sizeof(device_file_t));

    if (ds->key) {

        if (!args[0] || !args[1]) {
            apr_file_printf(ds->err, "%s is required.\n", ds->key);
            return APR_EINVAL;
        }
        else {

            int exact = 0;

            apr_array_header_t *options = apr_array_make(ds->pool, 10, sizeof(char *));

            status = device_get(ds, args[0], options, &ds->keyval, &ds->keypath, &exact);

            if (APR_SUCCESS != status) {
                return status;
            }

            if (!exact) {
                apr_file_printf(ds->err, "%s was not found.\n", args[0]);
                return APR_EINVAL;
            }
        }

        args += 2;
    }

    while (args && *args) {

        const char *arg = *(args++);

        if (!key) {
            key = arg;
            continue;
        }
        else {
            val = arg;
        }

        status = device_parse(ds, key, val, files);

        if (APR_SUCCESS != status) {
            break;
        }

        key = NULL;
        val = NULL;
    }

    if (key && !val) {
        apr_file_printf(ds->err, "argument '%s' has no corresponding value.\n",
                apr_pescape_echo(ds->pool, key, 1));
        return APR_EINVAL;
    }

    if (APR_SUCCESS == status) {
        status = device_files(ds, files);
    }

    return status;
}

static apr_status_t device_remove(device_set_t *ds, const char **args)
{
    apr_dir_t *thedir;
    apr_finfo_t dirent;

    char *pwd;
    const char *keyval = NULL, *keypath = NULL, *backup;
    apr_status_t status = APR_SUCCESS;

    apr_array_header_t *options = apr_array_make(ds->pool, 10, sizeof(char *));

    if (!args[0]) {
        apr_file_printf(ds->err, "%s is required.\n", ds->key);
        return status;
    }
    if (args[1] && args[2]) {
        apr_file_printf(ds->err, "no options are permitted other than %s.\n", ds->key);
        return status;
    }
    else {
        status = device_get(ds, args[0], options, &keyval, &keypath, NULL);

        if (APR_SUCCESS != status) {
            return status;
        }
    }

    /* save the present working directory */
    status = apr_filepath_get(&pwd, APR_FILEPATH_NATIVE, ds->pool);
    if (APR_SUCCESS != status) {
        apr_file_printf(ds->err, "could not remove '%s' (cwd): %pm\n", keyval, &status);
        return status;
    }

    /*
     * Remove is dangerous, so we sanity check on first pass.
     *
     * Any hidden files, any directories, we don't touch at all.
     */

    if ((status = apr_dir_open(&thedir, keypath, ds->pool)) != APR_SUCCESS) {

        /* could not open directory, skip */
        apr_file_printf(ds->err, "could not remove '%s': %pm\n", keyval, &status);

        return status;
    }

    do {
        status = apr_dir_read(&dirent,
                APR_FINFO_TYPE | APR_FINFO_NAME | APR_FINFO_WPROT, thedir);
        if (APR_STATUS_IS_INCOMPLETE(status)) {
            continue; /* ignore un-stat()able files */
        } else if (APR_STATUS_IS_ENOENT(status)) {
            break;
        } else if (status != APR_SUCCESS) {
            apr_file_printf(ds->err,
                    "could not remove '%s' (not accessible): %pm\n", keyval,
                    &status);
            break;
        }

        /* ignore current and parent, fail on hidden files */
        if (dirent.name[0] == '.') {
            if (!dirent.name[1]) {
                /* "." */
                continue;
            }
            else if (dirent.name[1] == '.' && !dirent.name[2]) {
                /* ".." */
                continue;
            }
            else {
                apr_file_printf(ds->err,
                        "could not remove '%s': unexpected hidden file: %s\n", keyval, dirent.name);
                apr_dir_close(thedir);
                return APR_EINVAL;
            }
        }

        switch (dirent.filetype) {
        case APR_DIR: {
            apr_file_printf(ds->err,
                    "could not remove '%s': unexpected directory: %s\n", keyval, dirent.name);
            apr_dir_close(thedir);
            return APR_EINVAL;
        }
        default:
            break;
        }

    } while (1);

    apr_dir_close(thedir);

    /*
     * Second step - try rename the directory.
     *
     * If we can't do this, give up without touching anything.
     */
    backup = apr_psprintf(ds->pool, "%s;%" APR_PID_T_FMT, keypath, getpid());

    if (APR_SUCCESS != (status = apr_file_rename(keypath, backup, ds->pool))) {
        apr_file_printf(ds->err, "could not remove '%s' (rename): %pm\n", keyval, &status);
        return status;
    }

    apr_file_remove(device_safename(ds->pool, keyval), ds->pool);

    /*
     * Third step - let's remove the files.
     *
     * If we fail here it's too late to recover, but our directory is
     * moved out the way.
     */

    /* jump into directory */
    status = apr_filepath_set(backup, ds->pool);
    if (APR_SUCCESS != status) {
        apr_file_printf(ds->err, "could not remove '%s' (chdir): %pm\n", keyval, &status);
        return status;
    }

    if ((status = apr_dir_open(&thedir, ".", ds->pool)) != APR_SUCCESS) {
        apr_file_printf(ds->err, "could not remove '%s' (open options): %pm\n", keyval, &status);
        return status;
    }

    do {
        status = apr_dir_read(&dirent,
                APR_FINFO_TYPE | APR_FINFO_NAME | APR_FINFO_WPROT, thedir);
        if (APR_STATUS_IS_INCOMPLETE(status)) {
            continue; /* ignore un-stat()able files */
        } else if (APR_STATUS_IS_ENOENT(status)) {
            break;
        } else if (status != APR_SUCCESS) {
            apr_file_printf(ds->err,
                    "could not remove '%s' (read options): %pm\n", keyval,
                    &status);
            break;
        }

        /* ignore current and parent */
        if (dirent.name[0] == '.') {
            if (!dirent.name[1]) {
                /* "." */
                continue;
            }
            else if (dirent.name[1] == '.' && !dirent.name[2]) {
                /* ".." */
                continue;
            }
        }

        if (APR_SUCCESS != (status = apr_file_remove(dirent.name, ds->pool))) {
            apr_file_printf(ds->err, "could not remove '%s' (delete option): %pm\n", keyval, &status);
            apr_dir_close(thedir);
            return status;
        }

    } while (1);

    apr_dir_close(thedir);

    /* change current working directory */
    status = apr_filepath_set(pwd, ds->pool);
    if (APR_SUCCESS != status) {
        apr_file_printf(ds->err, "could not remove '%s' (chdir): %pm\n", keyval, &status);
        return status;
    }

    /*
     * Last step - remove that directory.
     */

    if ((status = apr_dir_remove(backup, ds->pool)) != APR_SUCCESS) {
        apr_file_printf(ds->err, "could not remove '%s': %pm\n", keyval, &status);
        return status;
    }

    return status;
}

static apr_status_t device_mark(device_set_t *ds, const char **args)
{
    apr_file_t *out;

    const char *keyval = NULL, *keypath = NULL;
    apr_status_t status = APR_SUCCESS;

    apr_array_header_t *options = apr_array_make(ds->pool, 10, sizeof(char *));

    if (!args[0]) {
        apr_file_printf(ds->err, "%s is required.\n", ds->key);
        return status;
    }
    if (args[1] && args[2]) {
        apr_file_printf(ds->err, "no options are permitted other than %s.\n", ds->key);
        return status;
    }
    else {
        status = device_get(ds, args[0], options, &keyval, &keypath, NULL);

        if (APR_SUCCESS != status) {
            return status;
        }
    }

    if (APR_SUCCESS != (status = apr_filepath_set(keypath, ds->pool))) {
        apr_file_printf(ds->err, "could not mark '%s' (chdir): %pm\n", keyval, &status);
    }
    else if (APR_SUCCESS
        != (status = apr_file_open(&out, DEVICE_REMOVE_MARKER, APR_FOPEN_CREATE | APR_FOPEN_WRITE,
            APR_FPROT_OS_DEFAULT, ds->pool))) {
        apr_file_printf(ds->err, "cannot create mark '%s': %pm\n", keyval,
            &status);
    }
    else if (APR_SUCCESS != (status = apr_file_close(out))) {
        apr_file_printf(ds->err, "cannot close mark '%s': %pm\n", keyval, &status);
    }
    else if (APR_SUCCESS
            != (status = apr_file_perms_set(DEVICE_REMOVE_MARKER,
                    APR_FPROT_OS_DEFAULT & ~DEVICE_FILE_UMASK))) {
        apr_file_printf(ds->err, "cannot set permissions to mark '%s': %pm\n",
                keyval, &status);
    }

    apr_file_remove(device_safename(ds->pool, keyval), ds->pool);

    return status;
}

int main(int argc, const char * const argv[])
{
    apr_getopt_t *opt;
    const char *optarg;
    device_pair_t *index;

    device_set_t ds = { 0 };

    int optch;
    apr_status_t status = 0;
    int complete = 0;
    device_optional_e optional = DEVICE_OPTIONAL;

    apr_int64_t bytes_min = 0;
    apr_int64_t bytes_max = 0;

    apr_int64_t sqlid_min = DEVICE_SQL_IDENTIFIER_DEFAULT_MIN;
    apr_int64_t sqlid_max = DEVICE_SQL_IDENTIFIER_DEFAULT_MAX;

    /* lets get APR off the ground, and make sure it terminates cleanly */
    if (APR_SUCCESS != (status = apr_app_initialize(&argc, &argv, NULL))) {
        return 1;
    }
    atexit(apr_terminate);

    if (APR_SUCCESS != (status = apr_pool_create_ex(&ds.pool, NULL, abortfunc, NULL))) {
        return 1;
    }

    apr_file_open_stderr(&ds.err, ds.pool);
    apr_file_open_stdin(&ds.in, ds.pool);
    apr_file_open_stdout(&ds.out, ds.pool);

    ds.path = argv[0];

    ds.pairs = apr_hash_make(ds.pool);

    apr_getopt_init(&opt, ds.pool, argc, argv);
    while ((status = apr_getopt_long(opt, cmdline_opts, &optch, &optarg))
            == APR_SUCCESS) {

        switch (optch) {
        case 'a': {
            ds.mode = DEVICE_ADD;
            ds.key = optarg;
            break;
        }
        case 'b': {
            ds.path = optarg;
            break;
        }
        case 'c': {
            complete = 1;
            break;
        }
        case 'd': {
            ds.mode = DEVICE_REMOVE;
            ds.key = optarg;
            break;
        }
        case 'm': {
            ds.mode = DEVICE_MARK;
            ds.key = optarg;
            break;
        }
        case 'o': {
            optional = DEVICE_OPTIONAL;
            break;
        }
        case 'r': {
            optional = DEVICE_REQUIRED;
            break;
        }
        case 's': {
            ds.mode = DEVICE_SET;
            ds.key = optarg;
            break;
        }
        case 'v': {
            version(ds.out);
            return 0;
        }
        case 'h': {
            help(ds.out, argv[0], NULL, 0, cmdline_opts);
            return 0;
        }
        case DEVICE_INDEX: {

            device_pair_t *pair = apr_pcalloc(ds.pool, sizeof(device_pair_t));

            pair->type = DEVICE_PAIR_INDEX;
            pair->key = optarg;
            pair->suffix = DEVICE_INDEX_SUFFIX;
            pair->optional = optional;

            apr_hash_set(ds.pairs, optarg, APR_HASH_KEY_STRING, pair);

            break;
        }
        case DEVICE_PORT: {

            device_pair_t *pair = apr_pcalloc(ds.pool, sizeof(device_pair_t));

            pair->type = DEVICE_PAIR_PORT;
            pair->key = optarg;
            pair->suffix = DEVICE_TXT_SUFFIX;
            pair->optional = optional;

            apr_hash_set(ds.pairs, optarg, APR_HASH_KEY_STRING, pair);

            break;
        }
        case DEVICE_UNPRIVILEGED_PORT: {

            device_pair_t *pair = apr_pcalloc(ds.pool, sizeof(device_pair_t));

            pair->type = DEVICE_PAIR_UNPRIVILEGED_PORT;
            pair->key = optarg;
            pair->suffix = DEVICE_TXT_SUFFIX;
            pair->optional = optional;

            apr_hash_set(ds.pairs, optarg, APR_HASH_KEY_STRING, pair);

            break;
        }
        case DEVICE_HOSTNAME: {

            device_pair_t *pair = apr_pcalloc(ds.pool, sizeof(device_pair_t));

            pair->type = DEVICE_PAIR_HOSTNAME;
            pair->key = optarg;
            pair->suffix = DEVICE_TXT_SUFFIX;
            pair->optional = optional;

            apr_hash_set(ds.pairs, optarg, APR_HASH_KEY_STRING, pair);

            break;
        }
        case DEVICE_FQDN: {

            device_pair_t *pair = apr_pcalloc(ds.pool, sizeof(device_pair_t));

            pair->type = DEVICE_PAIR_FQDN;
            pair->key = optarg;
            pair->suffix = DEVICE_TXT_SUFFIX;
            pair->optional = optional;

            apr_hash_set(ds.pairs, optarg, APR_HASH_KEY_STRING, pair);

            break;
        }
        case DEVICE_SELECT: {

            device_pair_t *pair = apr_pcalloc(ds.pool, sizeof(device_pair_t));

            pair->type = DEVICE_PAIR_SELECT;
            pair->key = optarg;
            pair->suffix = DEVICE_TXT_SUFFIX;
            pair->optional = optional;
            pair->sl.bases = ds.select_bases;

            apr_hash_set(ds.pairs, optarg, APR_HASH_KEY_STRING, pair);

            ds.select_bases = NULL;

            break;
        }
        case DEVICE_SELECT_BASE: {

            const char **base;

            if (!ds.select_bases) {
                ds.select_bases = apr_array_make(ds.pool, 2, sizeof(const char *));
            }
            base = apr_array_push(ds.select_bases);
            base[0]= optarg;

            break;
        }
        case DEVICE_BYTES: {

            device_pair_t *pair = apr_pcalloc(ds.pool, sizeof(device_pair_t));

            pair->type = DEVICE_PAIR_BYTES;
            pair->key = optarg;
            pair->suffix = DEVICE_TXT_SUFFIX;
            pair->optional = optional;
            pair->b.min = bytes_min;
            pair->b.max = bytes_max;

            apr_hash_set(ds.pairs, optarg, APR_HASH_KEY_STRING, pair);

            break;
        }
        case DEVICE_BYTES_MIN: {

            status = device_parse_int64(&ds, optarg, &bytes_min);
            if (APR_SUCCESS != status) {
                exit(2);
            }

            break;
        }
        case DEVICE_BYTES_MAX: {

            status = device_parse_int64(&ds, optarg, &bytes_max);
            if (APR_SUCCESS != status) {
                exit(2);
            }

            break;
        }
        case DEVICE_SYMLINK: {

            device_pair_t *pair = apr_pcalloc(ds.pool, sizeof(device_pair_t));

            pair->type = DEVICE_PAIR_SYMLINK;
            pair->key = optarg;
            pair->suffix = ds.symlink_suffix ? ds.symlink_suffix  : DEVICE_NONE_SUFFIX;
            pair->optional = optional;
            pair->s.bases = ds.symlink_bases;

            apr_hash_set(ds.pairs, optarg, APR_HASH_KEY_STRING, pair);

            ds.symlink_bases = NULL;

            break;
        }
        case DEVICE_SYMLINK_BASE: {

            const char **base;

            if (!ds.symlink_bases) {
                ds.symlink_bases = apr_array_make(ds.pool, 2, sizeof(const char *));
            }
            base = apr_array_push(ds.symlink_bases);
            base[0]= optarg;

            break;
        }
        case DEVICE_SYMLINK_SUFFIX: {
            ds.symlink_suffix = optarg;
            ds.symlink_suffix_len = strlen(optarg);
            break;
        }
        case DEVICE_SQL_IDENTIFIER: {

            device_pair_t *pair = apr_pcalloc(ds.pool, sizeof(device_pair_t));

            pair->type = DEVICE_PAIR_SQL_IDENTIFIER;
            pair->key = optarg;
            pair->suffix = DEVICE_SQL_SUFFIX;
            pair->optional = optional;
            pair->q.min = sqlid_min;
            pair->q.max = sqlid_max;

            apr_hash_set(ds.pairs, optarg, APR_HASH_KEY_STRING, pair);

            break;
        }
        case DEVICE_SQL_DELIMITED_IDENTIFIER: {

            device_pair_t *pair = apr_pcalloc(ds.pool, sizeof(device_pair_t));

            pair->type = DEVICE_PAIR_SQL_DELIMITED_IDENTIFIER;
            pair->key = optarg;
            pair->suffix = DEVICE_TXT_SUFFIX;
            pair->optional = optional;
            pair->q.min = sqlid_min;
            pair->q.max = sqlid_max;

            apr_hash_set(ds.pairs, optarg, APR_HASH_KEY_STRING, pair);

            break;
        }
        case DEVICE_SQL_IDENTIFIER_MIN: {

            status = device_parse_int64(&ds, optarg, &sqlid_min);
            if (APR_SUCCESS != status) {
                exit(2);
            }

            break;
        }
        case DEVICE_SQL_IDENTIFIER_MAX: {

            status = device_parse_int64(&ds, optarg, &sqlid_max);
            if (APR_SUCCESS != status) {
                exit(2);
            }

            break;
        }
        case DEVICE_USER: {

            device_pair_t *pair = apr_pcalloc(ds.pool, sizeof(device_pair_t));

            pair->type = DEVICE_PAIR_USER;
            pair->key = optarg;
            pair->suffix = DEVICE_USER_SUFFIX;
            pair->optional = optional;
            pair->u.groups = ds.user_groups;

            apr_hash_set(ds.pairs, optarg, APR_HASH_KEY_STRING, pair);

            ds.user_groups = NULL;

            break;
        }
        case DEVICE_USER_GROUP: {

            const char **groups;

            if (!ds.user_groups) {
                ds.user_groups = apr_array_make(ds.pool, 2, sizeof(const char *));
            }
            groups = apr_array_push(ds.user_groups);
            groups[0]= optarg;

            break;
        }
        case DEVICE_DISTINGUISHED_NAME: {

            device_pair_t *pair = apr_pcalloc(ds.pool, sizeof(device_pair_t));

            pair->type = DEVICE_PAIR_DISTINGUISHED_NAME;
            pair->key = optarg;
            pair->suffix = DEVICE_DISTINGUISHED_NAME_SUFFIX;
            pair->optional = optional;

            apr_hash_set(ds.pairs, optarg, APR_HASH_KEY_STRING, pair);

            break;
        }
        }

        if (complete) {
            break;
        }

    }
    if (APR_SUCCESS != status && APR_EOF != status) {
        return help(ds.err, argv[0], NULL, EXIT_FAILURE, cmdline_opts);
    }

    if (ds.key) {

        index = apr_hash_get(ds.pairs, ds.key, APR_HASH_KEY_STRING);
        if (index) {

            /* index parameter always required */
            index->optional = DEVICE_REQUIRED;

            /* mark the index */
            index->index = DEVICE_INDEXED;

        }
        else {
            if (ds.mode == DEVICE_ADD) {
                return help(ds.err, argv[0], "The --add parameter was not found on the command line.",
                        EXIT_FAILURE, cmdline_opts);
            }

            if (ds.mode == DEVICE_REMOVE) {
                return help(ds.err, argv[0], "The --remove parameter was not found on the command line.",
                        EXIT_FAILURE, cmdline_opts);
            }

            if (ds.mode == DEVICE_SET) {
                return help(ds.err, argv[0], "The --set parameter was not found on the command line.",
                        EXIT_FAILURE, cmdline_opts);
            }
        }
    }

    if (complete) {

        status = device_complete(&ds, opt->argv + opt->ind);

        switch (status) {
        case APR_SUCCESS:
        case APR_INCOMPLETE:
            /* valid or incomplete are all ok */
            exit(0);
        default:
            /* otherwise light up the option in red */
            exit(1);
        }

    }
    else if (ds.mode == DEVICE_ADD) {

        status = device_add(&ds, opt->argv + opt->ind);

        if (APR_SUCCESS != status) {
            exit(1);
        }
    }
    else if (ds.mode == DEVICE_REMOVE) {

        status = device_remove(&ds, opt->argv + opt->ind);

        if (APR_SUCCESS != status) {
            exit(1);
        }
    }
    else if (ds.mode == DEVICE_MARK) {

        status = device_mark(&ds, opt->argv + opt->ind);

        if (APR_SUCCESS != status) {
            exit(1);
        }
    }
    else {

        status = device_set(&ds, opt->argv + opt->ind);

        if (APR_SUCCESS != status) {
            exit(1);
        }
    }

    exit(0);
}
