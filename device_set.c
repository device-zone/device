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

#include <stdlib.h>

#include <apr.h>
#include <apr_escape.h>
#include <apr_file_io.h>
#include <apr_getopt.h>
#include <apr_lib.h>
#include <apr_hash.h>
#include <apr_strings.h>

#include "device_util.h"

#include "config.h"

#define DEVICE_PORT 257
#define DEVICE_UNPRIVILEGED_PORT 258
#define DEVICE_HOSTNAME 259
#define DEVICE_FQDN 260
#define DEVICE_SELECT 261
#define DEVICE_BYTES 262
#define DEVICE_BYTES_MIN 263
#define DEVICE_BYTES_MAX 264

#define DEVICE_TXT ".txt"

typedef struct device_set_t {
    apr_pool_t *pool;
    apr_pool_t *tpool;
    apr_file_t *err;
    apr_file_t *in;
    apr_file_t *out;
    apr_hash_t *pairs;
    const char *path;
} device_set_t;

#define DEVICE_PORT_MIN 0
#define DEVICE_PORT_MAX 65535
#define DEVICE_PORT_UNPRIVILEGED_MIN 1025
#define DEVICE_PORT_UNPRIVILEGED_MAX 49151
#define DEVICE_HOSTNAME_MIN 1
#define DEVICE_HOSTNAME_MAX 63
#define DEVICE_SELECT_MAX 80

#define DEVICE_FILE_UMASK (0x0113)

typedef enum device_pair_e {
    DEVICE_PAIR_PORT,
    DEVICE_PAIR_UNPRIVILEGED_PORT,
    DEVICE_PAIR_HOSTNAME,
    DEVICE_PAIR_FQDN,
    DEVICE_PAIR_SELECT,
    DEVICE_PAIR_BYTES
} device_pair_e;

typedef enum device_optional_e {
    DEVICE_OPTIONAL,
    DEVICE_REQUIRED
} device_optional_e;

typedef struct device_pair_bytes_t {
    apr_int64_t min;
    apr_int64_t max;
} device_pair_bytes_t;

typedef struct device_pair_t {
    const char *key;
    const char *suffix;
    device_pair_e type;
    device_optional_e optional;
    union {
        device_pair_bytes_t b;
    };
} device_pair_t;

typedef struct device_file_t {
    const char *key;
    char *template;
    const char *dest;
    const char *val;
} device_file_t;

static const apr_getopt_option_t
    cmdline_opts[] =
{
    /* commands */
    { "help", 'h', 0, "  -h, --help\t\t\tDisplay this help message." },
    { "version", 'v', 0,
        "  -v, --version\t\t\tDisplay the version number." },
    { "base", 'b', 1, "  -b, --base path\t\tBase path in which to search for option files." },
    { "complete", 'c', 0, "  -c, --complete\t\tPerform command line completion." },
    { "optional", 'o', 0, "  -o, --optional\t\tOptions declared after this are optional. This\n\t\t\t\tis the default." },
    { "required", 'r', 0, "  -r, --required\t\tOptions declared after this are required." },
    { "port", DEVICE_PORT, 1, "  --port=name\t\t\tParse a port. Ports are integers in the range\n\t\t\t\t0 to 65535." },
    { "unprivileged-port", DEVICE_UNPRIVILEGED_PORT, 1, "  --unprivileged-port=name\tParse an unprivileged port. Unprivileged ports are\n\t\t\t\tintegers in the range 1025 to 49151." },
    { "hostname", DEVICE_HOSTNAME, 1, "  --hostname=name\t\tParse a hostname. Hostnames consist of the\n\t\t\t\tcharacters a-z, 0-9, or a hyphen. Hostname\n\t\t\t\tcannot start with a hyphen." },
    { "fqdn", DEVICE_FQDN, 1, "  --fqdn=name\t\t\tParse a fully qualified domain name. FQDNs\n\t\t\t\tconsist of labels containing the characters\n\t\t\t\ta-z, 0-9, or a hyphen, and cannot start with\n\t\t\t\ta hyphen. Labels are separated by dots, and\n\t\t\t\tthe total length cannot exceed 253 characters." },
    { "select", DEVICE_SELECT, 1, "  --select=name\t\t\tParse a selection from a file containing\n\t\t\t\toptions. The file containing options is\n\t\t\t\tsearched relative to the base path, and has\n\t\t\t\tthe same name as the result file. Unambiguous\n\t\t\t\tprefix matches are accepted." },
    { "bytes-minimum", DEVICE_BYTES_MIN, 1, "  --bytes-minimum=bytes\t\tLower limit used by the next bytes option. Zero\n\t\t\t\tfor no limit." },
    { "bytes-maximum", DEVICE_BYTES_MAX, 1, "  --bytes-maximum=bytes\t\tUpper limit used by the next bytes option. Zero\n\t\t\t\tfor no limit." },
    { "bytes", DEVICE_BYTES, 1, "  --bytes=name\t\t\tParse a positive integer containing bytes.\n\t\t\t\tOptional modifiers like B, kB, KiB, MB, MiB,\n\t\t\t\tGB, GiB, TB, TiB, PB, PiB, EB, EiB are accepted,\n\t\t\t\tand the given string is expanded into a byte\n\t\t\t\tvalue. Modifiers outside of the specified byte\n\t\t\t\trange are ignored." },
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
            "  In this example, set a host and a port.\n"
            "\n"
            "\t~$ device-set --hostname host --port port -- host=localhost port=22\n"
            "\n"
            "  Here we perform command line completion on the given option.\n"
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
    apr_file_t *in;
    const char *optname;
    char *optpath;
    apr_off_t end = 0, start = 0;
    apr_status_t status;
    apr_size_t arglen = arg ? strlen(arg) : 0;

    /* options are in same libexec directory as command */
    optname = apr_pstrcat(ds->pool, pair->key, pair->suffix, NULL);
    if (APR_SUCCESS
            != (status = apr_filepath_merge(&optpath, ds->path,
                    optname, APR_FILEPATH_NOTABOVEROOT, ds->pool))) {
        apr_file_printf(ds->err, "cannot merge options '%s': %pm\n", pair->key,
                &status);
    }

    /* open the options */
    else if (APR_SUCCESS
            != (status = apr_file_open(&in, optpath, APR_FOPEN_READ,
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

        while (APR_SUCCESS == (status = apr_file_gets(buffer, size, in))) {

            const char **possible;
            apr_size_t optlen = strlen(buffer);

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

            if (!strncmp(arg, buffer, arglen)) {

                const char **opt = apr_array_push(options);

                opt[0] = apr_pstrcat(ds->pool,
                        pair->optional == DEVICE_OPTIONAL ? "-" : "*",
                        device_pescape_shell(ds->pool, pair->key), "=",
                        device_pescape_shell(ds->pool, buffer),
                        NULL);

                if (option) {
                    option[0] = possible[0];
                }
            }

        }

        apr_file_close(in);

        if (APR_EOF == status) {

            if (*option) {
                if (options->nelts == 1) {
                    /* all ok */
                }
                else {
                    if (end < DEVICE_SELECT_MAX) {
                        apr_file_printf(ds->err, "argument '%s' must be one of: %s\n",
                                apr_pescape_echo(ds->pool, pair->key, 1), apr_array_pstrcat(ds->pool, possibles, ','));
                    }
                    else {
                        apr_file_printf(ds->err, "argument '%s': value does not match a valid option.\n",
                                apr_pescape_echo(ds->pool, pair->key, 1));
                    }
                    return APR_INCOMPLETE;
                }
            }

            status = APR_SUCCESS;
        }
        else {
            apr_file_printf(ds->err, "cannot read option '%s': %pm\n", pair->key,
                    &status);
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
    apr_file_printf(ds->err, "argument '%s' must be one of: %s\n",
            apr_pescape_echo(ds->pool, pair->key, 1), apr_array_pstrcat(ds->pool, possibles, ','));
    return APR_INCOMPLETE;
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

    if (value) {

        device_pair_t *pair;

        pair = apr_hash_get(ds->pairs, key, APR_HASH_KEY_STRING);

        if (pair) {

            apr_array_header_t *options = apr_array_make(ds->pool, 10, sizeof(char *));
            int i;

            switch (pair->type) {
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

static apr_status_t device_files(device_set_t *ds, apr_array_header_t *files)
{
    apr_status_t status = APR_SUCCESS;
    int i;

    /* try to write */
    for (i = 0; i < files->nelts; i++)
    {
        apr_file_t *out;

        device_file_t *file = &APR_ARRAY_IDX(files, i, device_file_t);

        /* write the result */
        if (APR_SUCCESS
                != (status = apr_file_mktemp(&out, file->template,
                        APR_FOPEN_CREATE | APR_FOPEN_WRITE | APR_FOPEN_EXCL,
                        ds->pool))) {
            apr_file_printf(ds->err, "cannot save '%s': %pm\n", file->key, &status);
            break;
        }
        else if (APR_SUCCESS != (status = apr_file_write_full(out, file->val, strlen(file->val), NULL))) {
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
            apr_file_printf(ds->err, "cannot set permissions on '%s': %pm\n", file->key, &status);
            break;
        }

    }

    /* could not write, try to rollback */
    if (APR_SUCCESS != status) {

        for (i = 0; i < files->nelts; i++) {

            device_file_t *file = &APR_ARRAY_IDX(files, i, device_file_t);

            if (APR_SUCCESS != (status = apr_file_remove(file->template, ds->pool))) {
                apr_file_printf(ds->err, "cannot move '%s': %pm\n", file->key, &status);
                break;
            }

        }

    }

    /* otherwise do the renames */
    else {

        for (i = 0; i < files->nelts; i++) {

            device_file_t *file = &APR_ARRAY_IDX(files, i, device_file_t);

            if (APR_SUCCESS != (status = apr_file_rename(file->template, file->dest, ds->pool))) {
                apr_file_printf(ds->err, "cannot move '%s': %pm\n", file->key, &status);
                break;
            }

        }

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

    while (args && *args) {

        device_file_t *file;
        const char *arg = *(args++);
        device_pair_t *pair;

        if (!key) {
            key = arg;
            continue;
        }
        else {
            val = arg;
        }

        /* look up the parameter */
        pair = apr_hash_get(ds->pairs, key, APR_HASH_KEY_STRING);

        if (pair) {

            apr_array_header_t *options = apr_array_make(ds->pool, (len / 2), sizeof(char *));

            switch (pair->type) {
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
            }

            file = apr_array_push(files);

            file->dest = apr_pstrcat(ds->pool, pair->key, pair->suffix, NULL);
            file->template = apr_pstrcat(ds->pool, file->dest, ".XXXXXX", NULL);
            file->key = key;
            file->val = val;

        }
        else {
            // FIXME: add option for an "overflow" of unknown arguments
            apr_file_printf(ds->err, "argument '%s' is not recognised.\n",
                    apr_pescape_echo(ds->pool, arg, 1));
            return APR_EINVAL;
        }

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

int main(int argc, const char * const argv[])
{
    apr_getopt_t *opt;
    const char *optarg;

    device_set_t ds = { 0 };

    int optch;
    apr_status_t status = 0;
    int complete = 0;
    device_optional_e optional = DEVICE_OPTIONAL;

    apr_int64_t bytes_min = 0;
    apr_int64_t bytes_max = 0;

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
        case 'b': {
            ds.path = optarg;
            break;
        }
        case 'c': {
            complete = 1;
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
        case 'v': {
            version(ds.out);
            return 0;
        }
        case 'h': {
            help(ds.out, argv[0], NULL, 0, cmdline_opts);
            return 0;
        }
        case DEVICE_PORT: {

            device_pair_t *pair = apr_pcalloc(ds.pool, sizeof(device_pair_t));

            pair->type = DEVICE_PAIR_PORT;
            pair->key = optarg;
            pair->suffix = DEVICE_TXT;
            pair->optional = optional;

            apr_hash_set(ds.pairs, optarg, APR_HASH_KEY_STRING, pair);

            break;
        }
        case DEVICE_UNPRIVILEGED_PORT: {

            device_pair_t *pair = apr_pcalloc(ds.pool, sizeof(device_pair_t));

            pair->type = DEVICE_PAIR_UNPRIVILEGED_PORT;
            pair->key = optarg;
            pair->suffix = DEVICE_TXT;
            pair->optional = optional;

            apr_hash_set(ds.pairs, optarg, APR_HASH_KEY_STRING, pair);

            break;
        }
        case DEVICE_HOSTNAME: {

            device_pair_t *pair = apr_pcalloc(ds.pool, sizeof(device_pair_t));

            pair->type = DEVICE_PAIR_HOSTNAME;
            pair->key = optarg;
            pair->suffix = DEVICE_TXT;
            pair->optional = optional;

            apr_hash_set(ds.pairs, optarg, APR_HASH_KEY_STRING, pair);

            break;
        }
        case DEVICE_FQDN: {

            device_pair_t *pair = apr_pcalloc(ds.pool, sizeof(device_pair_t));

            pair->type = DEVICE_PAIR_FQDN;
            pair->key = optarg;
            pair->suffix = DEVICE_TXT;
            pair->optional = optional;

            apr_hash_set(ds.pairs, optarg, APR_HASH_KEY_STRING, pair);

            break;
        }
        case DEVICE_SELECT: {

            device_pair_t *pair = apr_pcalloc(ds.pool, sizeof(device_pair_t));

            pair->type = DEVICE_PAIR_SELECT;
            pair->key = optarg;
            pair->suffix = DEVICE_TXT;
            pair->optional = optional;

            apr_hash_set(ds.pairs, optarg, APR_HASH_KEY_STRING, pair);

            break;
        }
        case DEVICE_BYTES: {

            device_pair_t *pair = apr_pcalloc(ds.pool, sizeof(device_pair_t));

            pair->type = DEVICE_PAIR_BYTES;
            pair->key = optarg;
            pair->suffix = DEVICE_TXT;
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
        }

    }
    if (APR_SUCCESS != status && APR_EOF != status) {
        return help(ds.err, argv[0], NULL, EXIT_FAILURE, cmdline_opts);
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
    else {

        status = device_set(&ds, opt->argv + opt->ind);

        if (APR_SUCCESS != status) {
            exit(1);
        }
    }

    exit(0);
}
