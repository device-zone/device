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
#include <apr_env.h>
#include <apr_escape.h>
#include <apr_file_io.h>
#include <apr_getopt.h>
#include <apr_lib.h>
#include <apr_hash.h>
#include <apr_strings.h>
#include <apr_thread_proc.h>
#include <apr_uri.h>
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
#if HAVE_LOCALE_H
#include <locale.h>
#endif
#if HAVE_LANGINFO_H
#include <langinfo.h>
#endif
#if HAVE_ICONV_H
#include <iconv.h>
#endif
#if HAVE_SELINUX_SELINUX_H
#include <selinux/selinux.h>
#include <selinux/context.h>
#endif
#if HAVE_LIBGEN_H
#include <libgen.h>
#endif

#define DEVICE_OPTIONAL 257
#define DEVICE_REQUIRED 258
#define DEVICE_INDEX 259
#define DEVICE_DEFAULT 260
#define DEVICE_PORT 261
#define DEVICE_UNPRIVILEGED_PORT 262
#define DEVICE_HOSTNAME 263
#define DEVICE_FQDN 264
#define DEVICE_SELECT 265
#define DEVICE_SELECT_BASE 266
#define DEVICE_SELECT_MATRIX 267
#define DEVICE_BYTES 268
#define DEVICE_BYTES_MIN 269
#define DEVICE_BYTES_MAX 270
#define DEVICE_SYMLINK 271
#define DEVICE_SYMLINK_BASE 272
#define DEVICE_SYMLINK_SUFFIX 273
#define DEVICE_SYMLINK_CONTEXT_TYPE 274
#define DEVICE_SYMLINK_MAGIC 275
#define DEVICE_SYMLINK_RECURSIVE 276
#define DEVICE_SQL_IDENTIFIER 277
#define DEVICE_SQL_DELIMITED_IDENTIFIER 278
#define DEVICE_SQL_IDENTIFIER_MIN 279
#define DEVICE_SQL_IDENTIFIER_MAX 280
#define DEVICE_USER_GROUP 281
#define DEVICE_USER 282
#define DEVICE_DISTINGUISHED_NAME 283
#define DEVICE_RELATION_BASE 284
#define DEVICE_RELATION_NAME 285
#define DEVICE_RELATION_SUFFIX 286
#define DEVICE_RELATION 287
#define DEVICE_POLAR 288
#define DEVICE_POLAR_DEFAULT 289
#define DEVICE_SWITCH 290
#define DEVICE_SWITCH_DEFAULT 291
#define DEVICE_INTEGER 292
#define DEVICE_INTEGER_MIN 293
#define DEVICE_INTEGER_MAX 294
#define DEVICE_TEXT 295
#define DEVICE_TEXT_MIN 296
#define DEVICE_TEXT_MAX 297
#define DEVICE_TEXT_FORMAT 298
#define DEVICE_HEX 299
#define DEVICE_HEX_MIN 300
#define DEVICE_HEX_MAX 301
#define DEVICE_HEX_CASE 302
#define DEVICE_HEX_WIDTH 303
#define DEVICE_URL_PATH 304
#define DEVICE_URL_PATH_ABEMPTY 305
#define DEVICE_URL_PATH_ABSOLUTE 306
#define DEVICE_URL_PATH_NOSCHEME 307
#define DEVICE_URL_PATH_ROOTLESS 308
#define DEVICE_URL_PATH_EMPTY 309
#define DEVICE_URL_PATH_MAX 310
#define DEVICE_URI 311
#define DEVICE_URI_ABSOLUTE 312
#define DEVICE_URI_RELATIVE 313
#define DEVICE_URI_MAX 314
#define DEVICE_URI_SCHEMES 315
#define DEVICE_ADDRESS 316
#define DEVICE_ADDRESS_MAILBOX 317
#define DEVICE_ADDRESS_ADDRSPEC 318
#define DEVICE_ADDRESS_LOCALPART 319
#define DEVICE_ADDRESS_MAX 320
#define DEVICE_ADDRESS_NOQUOTES 321
#define DEVICE_ADDRESS_FILESAFE 322
#define DEVICE_FLAG 323
#define DEVICE_SHOW_INDEX 324
#define DEVICE_SHOW_FLAGS 325
#define DEVICE_SHOW_TABLE 326
#define DEVICE_COMMAND 327

#define DEVICE_INDEX_SUFFIX ".txt"
#define DEVICE_TXT_SUFFIX ".txt"
#define DEVICE_SQL_SUFFIX ".txt"
#define DEVICE_USER_SUFFIX ".txt"
#define DEVICE_DISTINGUISHED_NAME_SUFFIX ".txt"
#define DEVICE_DIR_SUFFIX ".d"
#define DEVICE_ENABLED_SUFFIX ".bin"
#define DEVICE_NONE_SUFFIX ""

#define DEVICE_ADD_MARKER "added"
#define DEVICE_SET_MARKER "updated"
#define DEVICE_REMOVE_MARKER "removed"

typedef enum device_mode_e {
    DEVICE_SET,
    DEVICE_ADD,
    DEVICE_REMOVE,
    DEVICE_MARK,
    DEVICE_REINDEX,
    DEVICE_RENAME,
    DEVICE_SHOW,
    DEVICE_LIST,
    DEVICE_EXEC,
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
    apr_array_header_t *relation_bases;
    apr_array_header_t *show_index;
    apr_array_header_t *show_flags;
    apr_array_header_t *show_table;
    const char *symlink_suffix;
    int symlink_suffix_len;
    const char *symlink_context_type;
    unsigned int symlink_recursive:1;
    const char *relation_name;
    int relation_name_len;
    const char *relation_prefix;
    int relation_prefix_len;
    const char *relation_suffix;
    int relation_suffix_len;
    apr_hash_t *schemes;
    char ** argv;
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
#define DEVICE_SYMLINK_ERROR "[missing]"
#define DEVICE_SQL_IDENTIFIER_DEFAULT_MIN 1
#define DEVICE_SQL_IDENTIFIER_DEFAULT_MAX 63
#define DEVICE_FILE_UMASK (0x0113)
#define DEVICE_POLAR_DEFAULT_VAL DEVICE_IS_NO
#define DEVICE_SWITCH_DEFAULT_VAL DEVICE_IS_OFF
#define DEVICE_RELATION_NONE "none"
#define DEVICE_RELATION_ERROR "[missing]"
#define DEVICE_HEX_CASE_VAL DEVICE_IS_LOWER
#define DEVICE_HEX_WIDTH_VAL 0
#define DEVICE_HEX_WIDTH_MAX 16
#define DEVICE_TEXT_MIN_DEFAULT 0
#define DEVICE_TEXT_MAX_DEFAULT 255
#define DEVICE_TEXT_FORMAT_DEFAULT "UTF-8"
#define DEVICE_URL_PATH_MAX_DEFAULT 256
#define DEVICE_URI_MAX_DEFAULT 256
#define DEVICE_USER_NONE "none"
#define DEVICE_ADDRESS_MAX_DEFAULT 256
#define DEVICE_ADDRESS_NOQUOTES_DEFAULT 1
#define DEVICE_ADDRESS_FILESAFE_DEFAULT 0

#define DEVICE_ADDRESS_LOCAL_PART_LIMIT 64
#define DEVICE_ADDRESS_DOMAIN_LABEL_LIMIT 63
#define DEVICE_ADDRESS_DOMAIN_LIMIT 255

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
    DEVICE_PAIR_DISTINGUISHED_NAME,
    DEVICE_PAIR_RELATION,
    DEVICE_PAIR_POLAR,
    DEVICE_PAIR_SWITCH,
    DEVICE_PAIR_INTEGER,
    DEVICE_PAIR_TEXT,
    DEVICE_PAIR_HEX,
    DEVICE_PAIR_URL_PATH,
    DEVICE_PAIR_URL_PATH_ABEMPTY,
    DEVICE_PAIR_URL_PATH_ABSOLUTE,
    DEVICE_PAIR_URL_PATH_NOSCHEME,
    DEVICE_PAIR_URL_PATH_ROOTLESS,
    DEVICE_PAIR_URL_PATH_EMPTY,
    DEVICE_PAIR_URI,
    DEVICE_PAIR_URI_ABSOLUTE,
    DEVICE_PAIR_URI_RELATIVE,
    DEVICE_PAIR_ADDRESS,
    DEVICE_PAIR_ADDRESS_LOCALPART,
    DEVICE_PAIR_ADDRESS_MAILBOX,
    DEVICE_PAIR_ADDRESS_ADDRSPEC,
} device_pair_e;

typedef enum device_optional_e {
    DEVICE_IS_OPTIONAL,
    DEVICE_IS_REQUIRED
} device_optional_e;

typedef enum device_index_e {
    DEVICE_IS_NORMAL,
    DEVICE_IS_INDEXED
} device_index_e;

typedef enum device_unique_e {
    DEVICE_IS_REPEATED,
    DEVICE_IS_UNIQUE
} device_unique_e;

typedef enum device_polar_e {
    DEVICE_IS_NO,
    DEVICE_IS_YES
} device_polar_e;

typedef enum device_switch_e {
    DEVICE_IS_OFF,
    DEVICE_IS_ON
} device_switch_e;

typedef enum device_set_e {
    DEVICE_IS_UNSET,
    DEVICE_IS_SET,
    DEVICE_IS_DEFAULT
} device_set_e;

typedef enum device_case_e {
    DEVICE_IS_LOWER,
    DEVICE_IS_UPPER
} device_case_e;

typedef struct device_pair_selects_t {
    apr_array_header_t *bases;
} device_pair_selects_t;

typedef struct device_pair_bytes_t {
    apr_uint64_t min;
    apr_uint64_t max;
} device_pair_bytes_t;

typedef struct device_pair_symlinks_t {
    apr_array_header_t *bases;
    const char *symlink_suffix;
    int symlink_suffix_len;
    const char *symlink_context_type;
    unsigned int symlink_recursive:1;
} device_pair_symlinks_t;

typedef struct device_pair_relations_t {
    apr_array_header_t *bases;
    const char *relation_name;
    int relation_name_len;
    const char *relation_prefix;
    int relation_prefix_len;
    const char *relation_suffix;
    int relation_suffix_len;
} device_pair_relations_t;

typedef struct device_pair_sqlid_t {
    apr_uint64_t min;
    apr_uint64_t max;
} device_pair_sqlid_t;

typedef struct device_pair_users_t {
    apr_array_header_t *groups;
} device_pair_users_t;

typedef struct device_pair_polars_t {
    const char *flag;
    device_polar_e polar_default;
} device_pair_polars_t;

typedef struct device_pair_switches_t {
    const char *flag;
    device_switch_e switch_default;
} device_pair_switches_t;

typedef struct device_pair_integer_t {
    apr_int64_t min;
    apr_int64_t max;
} device_pair_integer_t;

typedef struct device_pair_hex_t {
    apr_int64_t min;
    apr_int64_t max;
    device_case_e cs;
    int width;
} device_pair_hex_t;

typedef struct device_pair_text_t {
    const char *format;
    apr_uint64_t min;
    apr_uint64_t max;
} device_pair_text_t;

typedef struct device_pair_url_path_t {
    apr_uint64_t max;
} device_pair_url_path_t;

typedef struct device_pair_uri_t {
    apr_hash_t *schemes;
    apr_uint64_t max;
} device_pair_uri_t;

typedef struct device_pair_address_t {
    unsigned int noquotes:1;
    unsigned int filesafe:1;
    apr_uint64_t max;
} device_pair_address_t;

typedef struct device_pair_t {
    const char *key;
    const char *suffix;
    const char *flag;
    const char *unset;
    device_pair_e type;
    device_optional_e optional;
    device_unique_e unique;
    device_index_e index;
    device_set_e set;
    union {
        device_pair_bytes_t b;
        device_pair_selects_t sl;
        device_pair_symlinks_t s;
        device_pair_sqlid_t q;
        device_pair_users_t u;
        device_pair_relations_t r;
        device_pair_polars_t p;
        device_pair_switches_t sw;
        device_pair_integer_t i;
        device_pair_text_t t;
        device_pair_hex_t h;
        device_pair_url_path_t up;
        device_pair_uri_t uri;
        device_pair_address_t a;
    };
} device_pair_t;

typedef struct device_file_t {
    const char *key;
    char *template;
    const char *dest;
    const char *backup;
    const char *val;
    const char *link;
    apr_int64_t order;
    device_index_e index;
    apr_filetype_e type;
} device_file_t;

typedef struct device_value_t {
    device_pair_t *pair;
    const char *value;
    apr_off_t len;
    unsigned int set:1;
} device_value_t;

typedef struct device_values_t {
    apr_array_header_t *values;
    apr_int64_t order;
} device_values_t;

typedef struct device_table_t {
    device_pair_t *pair;
    apr_array_header_t *values;
    const char *flag;
    int max;
} device_table_t;

typedef struct device_row_t {
    apr_array_header_t *indexes;
    apr_array_header_t *flags;
    apr_array_header_t *values;
    const char *keyval;
    apr_int64_t order;
} device_row_t;

static const apr_getopt_option_t
    cmdline_opts[] =
{
    /* commands */
    { "help", 'h', 0, "  -h, --help\t\t\tDisplay this help message." },
    { "version", 'v', 0,
        "  -v, --version\t\t\tDisplay the version number." },
    { "base", 'b', 1, "  -b, --base=path\t\tBase path in which to search for option files." },
    { "complete", 'c', 0, "  -c, --complete\t\tOutput values so the device shell can perform\n\t\t\t\tcommand line completion. Each completion is\n\t\t\t\tprefixed with '-' for optional completions and\n\t\t\t\t'*' for required completions. All non-prefixed\n\t\t\t\tstrings are ignored." },
    { "optional", DEVICE_OPTIONAL, 0, "  --optional\t\t\tOptions declared after this are optional. This\n\t\t\t\tis the default." },
    { "required", DEVICE_REQUIRED, 0, "  --required\t\t\tOptions declared after this are required." },
    { "add", 'a', 1, "  -a, --add=name\t\tAdd a new set of options, named by the key\n\t\t\t\tspecified, which becomes required. A file \n\t\t\t\tcalled '" DEVICE_ADD_MARKER "' will be created in the newly\n\t\t\t\tcreated directory to indicate the directory\n\t\t\t\tshould be processed." },
    { "remove", 'd', 1, "  -d, --remove=name\t\tRemove a set of options, named by the key\n\t\t\t\tspecified. The removal takes place immediately." },
    { "mark", 'm', 1, "  -m, --mark=name\t\tMark a set of options for removal, named by the\n\t\t\t\tkey specified. The actual removal is expected\n\t\t\t\tto be done by the script that processes this\n\t\t\t\toption. A file called '" DEVICE_REMOVE_MARKER "' will be created\n\t\t\t\tin the directory to indicate the directory\n\t\t\t\tshould be processed for removal." },
    { "set", 's', 1, "  -s, --set=name\t\tSet an option among a set of options, named by\n\t\t\t\tthe key specified. A file called '" DEVICE_SET_MARKER "' is\n\t\t\t\tcreated to indicate that settings should be\n\t\t\t\tprocessed for update." },
    { "rename", 'n', 1, "  -n, --rename=name\t\tRename an option among a set of options, named by\n\t\t\t\tthe key specified. Other options may be set at\n\t\t\t\tthe same time. A file called '" DEVICE_SET_MARKER "' is\n\t\t\t\tcreated to indicate that settings should be\n\t\t\t\tprocessed for update." },
    { "reindex", 'r', 1, "  -r, --reindex=name\t\tReindex all options of type index, removing gaps\n\t\t\t\tin numbering. Multiple indexes can be specified\n\t\t\t\tat the same time." },
    { "show", 'g', 1, "  -g, --show=name\t\tShow options in a set of options, named by\n\t\t\t\tthe key specified. To show\n\t\t\t\tunindexed options in the current directory,\n\t\t\t\tspecify '-'." },
#if 1
    { "exec", 'e', 1, "  -e, --exec\t\t\tPass the options in a set of options to an\n\t\t\t\texecutable, named by the key specified. To pass\n\t\t\t\tunindexed options in the current directory,\n\t\t\t\tspecify '-'. The options are written to\n\t\t\t\tenvironment variables prefixed with 'DEVICE_'\n\t\t\t\tand passed to the executable defined with\n\t\t\t\t--exec-command." },
#endif
#if 0
    { "list", 'l', 0, "  -l, --list\t\t\tList the options in a set of options." },
#endif
    { "default", DEVICE_DEFAULT, 1, "  --default=value\t\tSet the default value of this option to be\n\t\t\t\tdisplayed when unset. Defaults to 'none'." },
    { "index", DEVICE_INDEX, 1, "  --index=name\t\t\tSet the index of this option within a set of\n\t\t\t\toptions. If set to a positive integer starting\n\t\t\t\tfrom zero, this option will be inserted at the\n\t\t\t\tgiven index and higher options moved one up to\n\t\t\t\tfit. If unset, or if larger than the index of\n\t\t\t\tthe last option, this option will be set as the\n\t\t\t\tlast option and others moved down to fit. If\n\t\t\t\tnegative, the option will be inserted at the\n\t\t\t\tend counting backwards." },
#if 0
    { "unique", DEVICE_UNIQUE, 1, "  --unique=name[,name]\tForce the set of options to be unique. A search will be performed of the given options, and if found, the attempt to add or set will fail." },
#endif
    { "port", DEVICE_PORT, 1, "  --port=name\t\t\tParse a port. Ports are integers in the range\n\t\t\t\t0 to 65535." },
    { "unprivileged-port", DEVICE_UNPRIVILEGED_PORT, 1, "  --unprivileged-port=name\tParse an unprivileged port. Unprivileged ports\n\t\t\t\tare integers in the range 1025 to 49151." },
    { "hostname", DEVICE_HOSTNAME, 1, "  --hostname=name\t\tParse a hostname. Hostnames consist of the\n\t\t\t\tcharacters a-z, 0-9, or a hyphen. Hostname\n\t\t\t\tcannot start with a hyphen." },
    { "fqdn", DEVICE_FQDN, 1, "  --fqdn=name\t\t\tParse a fully qualified domain name. FQDNs\n\t\t\t\tconsist of labels containing the characters\n\t\t\t\ta-z, 0-9, or a hyphen, and cannot start with\n\t\t\t\ta hyphen. Labels are separated by dots, and\n\t\t\t\tthe total length cannot exceed 253 characters." },
#if 0
    { "select-matrix", DEVICE_SELECT_MATRIX, 1, "  --select-matrix=file\t\tCSV file containing valid combinations for\n\t\t\t\tselections. More than one file can be specified.\n\t\t\t\tThe CSV file is considered valid for all\n\t\t\t\tsubsequent select options." },
#endif
    { "select-base", DEVICE_SELECT_BASE, 1, "  --select-base=file\t\tBase files containing options for possible\n\t\t\t\tselections. More than one file can be specified." },
    { "select", DEVICE_SELECT, 1, "  --select=name\t\t\tParse a selection from a file containing\n\t\t\t\toptions. The file containing options is\n\t\t\t\tsearched relative to the base path, and has\n\t\t\t\tthe same name as the result file. Unambiguous\n\t\t\t\tprefix matches are accepted." },
    { "bytes-minimum", DEVICE_BYTES_MIN, 1, "  --bytes-minimum=bytes\t\tLower limit used by the next bytes option. Zero\n\t\t\t\tfor no limit." },
    { "bytes-maximum", DEVICE_BYTES_MAX, 1, "  --bytes-maximum=bytes\t\tUpper limit used by the next bytes option. Zero\n\t\t\t\tfor no limit." },
    { "bytes", DEVICE_BYTES, 1, "  --bytes=name\t\t\tParse a positive integer containing bytes.\n\t\t\t\tOptional modifiers like B, kB, KiB, MB, MiB,\n\t\t\t\tGB, GiB, TB, TiB, PB, PiB, EB, EiB are accepted,\n\t\t\t\tand the given string is expanded into a byte\n\t\t\t\tvalue. Modifiers outside of the specified byte\n\t\t\t\trange are ignored." },
    { "symlink-base", DEVICE_SYMLINK_BASE, 1, "  --symlink-base=path\t\tBase path containing targets for symbolic links.\n\t\t\t\tMore than one path can be specified. In the case\n\t\t\t\tof collision, the earliest match wins." },
    { "symlink-suffix", DEVICE_SYMLINK_SUFFIX, 1, "  --symlink-suffix=suffix\tLimit targets for symbolic links to this suffix." },
#if HAVE_SELINUX_SELINUX_H
    { "symlink-context-type", DEVICE_SYMLINK_CONTEXT_TYPE, 1, "  --symlink-context-type=type\tLimit targets for symbolic links to this SELinux\n\t\t\t\tcontext type." },
#endif
#if 0
    { "symlink-magic", DEVICE_SYMLINK_MAGIC, 1, "  --symlink-magic=magic\tLimit targets for symbolic links to this magic file definition." },
#endif
    { "symlink-recursive", DEVICE_SYMLINK_RECURSIVE, 0, "  --symlink-recursive\t\tAllow targets for symbolic links to exist\n\t\t\t\trecursively within a directory tree." },
    { "symlink", DEVICE_SYMLINK, 1, "  --symlink=name\t\tParse a selection from a list of files or\n\t\t\t\tdirectories matching the symlink-path, and save\n\t\t\t\tthe result as a symlink. If optional, the special\n\t\t\t\tvalue 'none' is accepted to mean no symlink." },
    { "sql-id", DEVICE_SQL_IDENTIFIER, 1, "  --sql-id=id\t\t\tSQL identifier in regular format. Regular\n\t\t\t\tidentifiers start with a letter (a-z, but also\n\t\t\t\tletters with diacritical marks and non-Latin\n\t\t\t\tletters) or an underscore (_). Subsequent\n\t\t\t\tcharacters in an identifier can be letters,\n\t\t\t\tunderscores, or digits (0-9). The resulting value\n\t\t\t\tdoes not need to be SQL escaped before use." },
    { "sql-delimited-id", DEVICE_SQL_DELIMITED_IDENTIFIER, 1, "  --sql-delimited-id=id\t\tSQL identifier in delimited format. Delimited\n\t\t\t\tidentifiers consist of any UTF8 non-zero character.\n\t\t\t\tThe resulting value must be SQL escaped separately\n\t\t\t\tbefore use." },
    { "sql-id-minimum", DEVICE_SQL_IDENTIFIER_MIN, 1, "  --sql-id-minimum=chars\tMinimum length used by the next\n\t\t\t\tsql-id/sql-delimited-id option. Defaults to 1." },
    { "sql-id-maximum", DEVICE_SQL_IDENTIFIER_MAX, 1, "  --sql-id-maximum=chars\tMaximum length used by the next\n\t\t\t\tsql-id/sql-delimited-id option. Defaults to 63." },
    { "user-group", DEVICE_USER_GROUP, 1, "  --unix-group=name\t\tLimit usernames to members of the given group. May\n\t\t\t\tbe specified more than once." },
    { "user", DEVICE_USER, 1, "  --user=name\t\t\tParse a user that exists on the system." },
    { "distinguished-name", DEVICE_DISTINGUISHED_NAME, 1, "  --distinguished-name=name\tParse an RFC4514 Distinguished Name." },
    { "relation-base", DEVICE_RELATION_BASE, 1, "  --relation-base=path\t\tBase path containing targets for related indexes.\n\t\t\t\tMore than one path can be specified. In the case\n\t\t\t\tof collision, the earliest match wins." },
    { "relation-name", DEVICE_RELATION_NAME, 1, "  --relation-name=name\t\tName of the file containing the related index. This\n\t\t\t\tfile is expected to exist under directories in the\n\t\t\t\tbase directory." },
    { "relation-suffix", DEVICE_RELATION_SUFFIX, 1, "  --relation-suffix=suffix\tLimit targets for relations to this suffix." },
    { "relation", DEVICE_RELATION, 1, "  --relation=name\t\tParse a selection from a set of related\n\t\t\t\tdirectories beneath the related-path, and save\n\t\t\t\tthe result as a symlink. If optional, the special\n\t\t\t\tvalue 'none' is accepted to mean no symlink." },
    { "polar-default", DEVICE_POLAR_DEFAULT, 1, "  --polar-default=[yes|no]\tPolar question default value, 'yes' or 'no'." },
    { "polar", DEVICE_POLAR, 1, "  --polar=name\t\t\tParse a polar question, with possible values\n\t\t\t\t'yes' and 'no'." },
    { "switch-default", DEVICE_SWITCH_DEFAULT, 1, "  --switch-default=[on|off]\tSwitch default value, 'on' or 'off'." },
    { "switch", DEVICE_SWITCH, 1, "  --switch=name\t\t\tParse a switch, with possible values 'on' and 'off'." },
    { "integer-minimum", DEVICE_INTEGER_MIN, 1, "  --integer-minimum=min\t\tLower limit used by the next integer option. \"min\"\n\t\t\t\tfor down to -9,223,372,036,854,775,808." },
    { "integer-maximum", DEVICE_INTEGER_MAX, 1, "  --integer-maximum=max\t\tUpper limit used by the next integer option. \"max\"\n\t\t\t\tfor up to 9,223,372,036,854,775,807." },
    { "integer", DEVICE_INTEGER, 1, "  --integer=number\t\tParse a 64 bit integer. Use \"min\" and \"max\" for lower\n\t\t\t\tand upper limit." },
    { "hex-minimum", DEVICE_HEX_MIN, 1, "  --hex-minimum=min\t\tLower limit used by the next hex option. \"min\"\n\t\t\t\tfor down to 0x0." },
    { "hex-maximum", DEVICE_HEX_MAX, 1, "  --hex-maximum=max\t\tUpper limit used by the next hex option. \"max\"\n\t\t\t\tfor up to 0xffffffffffffffff." },
    { "hex-case", DEVICE_HEX_CASE, 1, "  --hex-case=upper|lower\tCase used by the next hex option. \"lower\" for\n\t\t\t\tlowercase, \"upper\" for uppercase. Defaults to \"lower\"." },
    { "hex-width", DEVICE_HEX_WIDTH, 1, "  --hex-width=width\t\tMinimum field width used by the next hex option.\n\t\t\t\tDefaults to zero." },
    { "hex", DEVICE_HEX, 1, "  --hex=number\t\t\tParse an unsigned 64 bit hex number. Use \"min\" and\n\t\t\t\t\"max\" for lower and upper limit." },
    { "text-format", DEVICE_TEXT_FORMAT, 1, "  --text-format=format\t\tFormat used by the next text option. Defaults to UTF-8." },
    { "text-minimum", DEVICE_TEXT_MIN, 1, "  --text-minimum=min\t\tMinimum length used by the next text option." },
    { "text-maximum", DEVICE_TEXT_MAX, 1, "  --text-maximum=max\t\tMaximum length used by the next text option." },
    { "text", DEVICE_TEXT, 1, "  --text=chars\t\t\tParse text, converting to given format (default UTF-8).\n\t\t\t\tInvalid text strings will be rejected." },
    { "url-path", DEVICE_URL_PATH, 1, "  --url-path=name\t\tParse the path component of a URL. The path is\n\t\t\t\tdefined by section 3.3 of RFC3986." },
    { "url-path-abempty", DEVICE_URL_PATH_ABEMPTY, 1, "  --url-path-abempty=name\tParse the absolute or empty path component of a URL.\n\t\t\t\tAbsolute or empty is defined by section 3.3 of RFC3986." },
    { "url-path-absolute", DEVICE_URL_PATH_ABSOLUTE, 1, "  --url-path-absolute=name\tParse the absolute path component of a URL. Absolute is\n\t\t\t\tdefined by section 3.3 of RFC3986." },
    { "url-path-noscheme", DEVICE_URL_PATH_NOSCHEME, 1, "  --url-path-noscheme=name\tParse the noscheme path component of a URL. Noscheme is\n\t\t\t\tdefined by section 3.3 of RFC3986." },
    { "url-path-rootless", DEVICE_URL_PATH_ROOTLESS, 1, "  --url-path-rootless=name\tParse the rootless path component of a URL. Rootless is\n\t\t\t\tdefined by section 3.3 of RFC3986." },
    { "url-path-empty", DEVICE_URL_PATH_EMPTY, 1, "  --url-path-empty=name\t\tParse the empty path component of a URL. Empty is\n\t\t\t\tdefined by section 3.3 of RFC3986." },
    { "url-path-maximum", DEVICE_URL_PATH_MAX, 1, "  --url-path-maximum=max\tMaximum length used by the next path component of a URL." },
    { "uri", DEVICE_URI, 1, "  --uri=name\t\t\tParse a URI. The URI is defined by RFC3986." },
    { "uri-absolute", DEVICE_URI_ABSOLUTE, 1, "  --uri-absolute=name\t\tParse an absolute URI. The absolute URI has a scheme\n\t\t\t\tand no fragment, and is defined by section 4.3 of RFC3986." },
    { "uri-relative", DEVICE_URI_RELATIVE, 1, "  --uri-relative=name\t\tParse a relative URI. The relative URI is defined by\n\t\t\t\tsection 4.2 of RFC3986." },
    { "uri-maximum", DEVICE_URI_MAX, 1, "  --uri-maximum=max\t\tMaximum length used by the next URI." },
    { "uri-schemes", DEVICE_URI_SCHEMES, 1, "  --uri-schemes=s1[,s2[...]]\tSchemes accepted by the next URI." },
#if 0
    { "address", DEVICE_ADDRESS, 1, "  --address=name\t\tParse an email address." },
    { "address-mailbox", DEVICE_ADDRESS_MAILBOX, 1, "  --address-mailbox=name\tParse an email address matching a mailbox." },
#endif
    { "address-addrspec", DEVICE_ADDRESS_ADDRSPEC, 1, "  --address-addrspec=name\tParse an email address matching an addr-spec. This is\n\t\t\t\tthe local part, followed by '@', followed by the domain." },
    { "address-localpart", DEVICE_ADDRESS_LOCALPART, 1, "  --address-localpart=name\tParse the local part of an email address." },
    { "address-maximum", DEVICE_ADDRESS_MAX, 1, "  --address-maximum=max\t\tMaximum length used by the next address." },
#if 0
    { "address-noquotes", DEVICE_ADDRESS_NOQUOTES, 1, "  --address-noquotes=[yes|no]\tDo not allow quoted literals in email addresses." },
#endif
    { "address-filesafe", DEVICE_ADDRESS_FILESAFE, 1, "  --address-filesafe=[yes|no]\tDo not allow characters in email addresses that\n\t\t\t\twould be unsafe in a filename. This excludes the\n\t\t\t\tcharacters '/' and '\\'." },
    { "flag", DEVICE_FLAG, 1, "  --flag=chars\t\t\tWhen showing a table, use the specified\n\t\t\t\tcharacter(s) to indicate the flag is set." },
    { "show-index", DEVICE_SHOW_INDEX, 1, "  --show-index=name[,name...]\tWhen showing a table, show the specified indexes\n\t\t\t\t~as the opening columns." },
    { "show-flags", DEVICE_SHOW_FLAGS, 1, "  --show-flags=name[,name...]\tWhen showing a table, show the specified polars\n\t\t\t\tor switches as flags." },
    { "show-table", DEVICE_SHOW_TABLE, 1, "  --show-table=name[,name...]\tWhen showing a table, show the specified entries\n\t\t\t\tin the given order." },
    { "command", DEVICE_COMMAND, 1, "  --command='cmd[ args]'\tRun the given command, parsing any options\n\t\t\t\tspecified. Option values are passed as\n\t\t\t\tenvironment variables prefixed with 'DEVICE_'.\n\t\t\t\tSee --exec." },
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

apr_uint64_t device_strtoui64(const char *nptr, char **endptr, int base)
{
    const char *s;
    apr_uint64_t acc;
    apr_uint64_t val;
    int any;
    char c;

    errno = 0;
    /*
     * Skip white space and pick up leading +/- sign if any.
     * If base is 0, allow 0x for hex and 0 for octal, else
     * assume decimal; if base is already 16, allow 0x.
     */
    s = nptr;
    do {
        c = *s++;
    } while (apr_isspace(c));
    if ((base == 0 || base == 16) &&
        c == '0' && (*s == 'x' || *s == 'X')) {
            c = s[1];
            s += 2;
            base = 16;
    }
    if (base == 0)
        base = c == '0' ? 8 : 10;
    acc = any = 0;
    if (base < 2 || base > 36) {
        errno = EINVAL;
        if (endptr != NULL)
            *endptr = (char *)(any ? s - 1 : nptr);
        return acc;
    }

    /* The classic bsd implementation requires div/mod operators
     * to compute a cutoff.  Benchmarking proves that is very, very
     * evil to some 32 bit processors.  Instead, look for underflow
     * in both the mult and add/sub operation.  Unlike the bsd impl,
     * we also work strictly in a signed int64 word as we haven't
     * implemented the unsigned type in win32.
     *
     * Set 'any' if any `digits' consumed; make it negative to indicate
     * overflow.
     */
    val = 0;
    for ( ; ; c = *s++) {
        if (c >= '0' && c <= '9')
            c -= '0';
#if (('Z' - 'A') == 25)
        else if (c >= 'A' && c <= 'Z')
            c -= 'A' - 10;
        else if (c >= 'a' && c <= 'z')
            c -= 'a' - 10;
#elif APR_CHARSET_EBCDIC
        else if (c >= 'A' && c <= 'I')
            c -= 'A' - 10;
        else if (c >= 'J' && c <= 'R')
            c -= 'J' - 19;
        else if (c >= 'S' && c <= 'Z')
            c -= 'S' - 28;
        else if (c >= 'a' && c <= 'i')
            c -= 'a' - 10;
        else if (c >= 'j' && c <= 'r')
            c -= 'j' - 19;
        else if (c >= 's' && c <= 'z')
            c -= 'z' - 28;
#else
#error "CANNOT COMPILE device_strtoui64(), only ASCII and EBCDIC supported"
#endif
        else
            break;
        if (c >= base)
            break;
        val *= base;
        if ( (any < 0)  /* already noted an over/under flow - short circuit */
           || (val < acc || (val += c) < acc)) {       /* overflow */
            any = -1;   /* once noted, over/underflows never go away */
#ifdef APR_STRTOI64_OVERFLOW_IS_BAD_CHAR
            break;
#endif
        } else {
            acc = val;
            any = 1;
        }
    }

    if (any < 0) {
        acc = UINT64_MAX;
        errno = ERANGE;
    } else if (!any) {
        errno = EINVAL;
    }
    if (endptr != NULL)
        *endptr = (char *)(any ? s - 1 : nptr);
    return (acc);
}

static int files_asc(const void *a, const void *b)
{
    const device_file_t *fa = a, *fb = b;

    return fa->order - fb->order;
}

static int files_desc(const void *a, const void *b)
{
    const device_file_t *fa = a, *fb = b;

    return fb->order - fa->order;
}

static int values_asc(const void *a, const void *b)
{
    const device_value_t *va = a, *vb = b;

    return strcmp(va->pair->key, vb->pair->key);
}

static int rows_asc(const void *a, const void *b)
{
    const device_row_t *va = a, *vb = b;

    if (va->order == vb->order) {

        if (va->keyval == vb->keyval) {
            return 0;
        }
        else if (!va->keyval) {
            return -1;
        }
        else if (!vb->keyval) {
            return 1;
        }

        return strcmp(va->keyval, vb->keyval);
    }

    return (va->order - vb->order);
}

static const char * device_hash_to_string(apr_pool_t *pool, apr_hash_t *hash)
{
    apr_hash_index_t *hi;
    void *v;
    const char *str;
    char *buf, *offset = NULL;
    apr_size_t len = 0;

    for (hi = apr_hash_first(pool, hash); hi; hi = apr_hash_next(hi)) {
        apr_hash_this(hi, NULL, NULL, &v);
        str = v;
        len += strlen(str);
        len++; /* commas plus terminating zero */
    }

    buf = offset = apr_palloc(pool, len);

    for (hi = apr_hash_first(pool, hash); hi; hi = apr_hash_next(hi)) {
        apr_hash_this(hi, NULL, NULL, &v);
        str = v;
        if (buf != offset) {
            offset = stpcpy(offset, ",");
        }
        offset = stpcpy(offset, str);
    }

    offset[0] = 0;

    return buf;
}

static apr_status_t device_file_open(device_set_t *ds, apr_pool_t *pool,
        const char *key, const char *filename, apr_file_t **file,
        apr_off_t *len)
{
    apr_file_t *in;
    apr_off_t end = 0, start = 0;

    apr_status_t status = APR_SUCCESS;

    /* open the file */
    if (APR_SUCCESS
            != (status = apr_file_open(&in, filename, APR_FOPEN_READ,
                    APR_FPROT_OS_DEFAULT, pool))) {
        apr_file_printf(ds->err, "cannot open option '%s': %pm\n", key,
                &status);
    }

    /* how long is the key? */
    else if (APR_SUCCESS
            != (status = apr_file_seek(in, APR_END, &end))) {
        apr_file_printf(ds->err, "cannot seek end of option '%s': %pm\n", key,
                &status);
    }

    /* back to the beginning */
    else if (APR_SUCCESS
            != (status = apr_file_seek(in, APR_SET, &start))) {
        apr_file_printf(ds->err, "cannot seek start of option '%s': %pm\n", key,
                &status);
    }

    else {
        file[0] = in;
        len[0] = end;
    }

    return status;
}

static apr_status_t device_file_read(device_set_t *ds, apr_pool_t *pool,
        const char *key, const char *filename, const char **value,
        apr_off_t *len)
{
    apr_file_t *in;

    char *val = NULL;

    apr_status_t status = APR_SUCCESS;

    /* open/seek the file */
    if (APR_SUCCESS
            != (status = device_file_open(ds, pool, key, filename, &in, len))) {
        /* error already handled */
    }

    else {
        apr_off_t size = len[0] + 1;
        val = apr_palloc(pool, size);
        val[len[0]] = 0;

        status = apr_file_gets(val, size, in);

        if (APR_EOF == status) {
            status = APR_SUCCESS;
        }
        if (APR_SUCCESS == status) {
            /* short circuit, all good */
            val = trim(val);
        }
        else {
            apr_file_printf(ds->err, "cannot read option set '%s': %pm\n", key,
                    &status);
        }

        apr_file_close(in);
    }

    if (APR_SUCCESS == status) {
        value[0] = val;
    }

    return status;
}

/*
 * Index is an integer between APR_INT64_MIN and APR_INT64_MAX inclusive.
 */
static apr_status_t device_parse_index(device_set_t *ds, device_pair_t *pair,
        const char *arg, const char **option, apr_array_header_t *files)
{
    char *end;

    apr_dir_t *thedir;
    apr_finfo_t dirent;

    apr_array_header_t *tfiles = apr_array_make(ds->pool, 16, sizeof(device_file_t));

    apr_status_t status;
    int found = 0;

    /* can an index be optional? */
    if (!arg || !arg[0]) {
        apr_file_printf(ds->err, "argument '%s': is empty.\n",
                apr_pescape_echo(ds->pool, pair->key, 1));
        return APR_INCOMPLETE;
    }

    apr_int64_t ind = apr_strtoi64(arg, &end, 10);
    if (end[0] || errno == ERANGE) {
        apr_file_printf(ds->err, "argument '%s': '%s' is not a valid index.\n",
                apr_pescape_echo(ds->pool, pair->key, 1),
                apr_pescape_echo(ds->pool, arg, 1));
        return APR_EINVAL;
    }

    if (!files) {
        return APR_SUCCESS;
    }

    /* make space for the index when needed */

    /* scan the directories to find a match */
    if ((status = apr_dir_open(&thedir, ".", ds->pool)) != APR_SUCCESS) {
        /* could not open directory, fail */
        apr_file_printf(ds->err, "could not open current directory: %pm\n", &status);
        return status;
    }

    do {

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
            char *val = NULL;
            apr_file_t *in;
            const char *indexname;
            char *indexpath, *path, *linkpath;
            apr_off_t end = 0, start = 0;

            apr_pool_create(&pool, ds->pool);

            indexname = apr_pstrcat(pool, pair->key, pair->suffix, NULL);
            if (APR_SUCCESS
                    != (status = apr_filepath_merge(&indexpath, dirent.name,
                            indexname, APR_FILEPATH_NOTABSOLUTE, pool))) {
                apr_file_printf(ds->err, "cannot merge option set key '%s': %pm\n", pair->key,
                        &status);
            }

            /* open the index */
            else if (APR_SUCCESS
                    != (status = apr_file_open(&in, indexpath, APR_FOPEN_READ,
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
                apr_file_printf(ds->err, "cannot seek start of option set '%s': %pm\n", pair->key,
                        &status);
            }

            else {
                int size = end + 1;
                val = apr_palloc(pool, size);
                val[end] = 0;

                status = apr_file_gets(val, size, in);

                if (APR_EOF == status) {
                    status = APR_SUCCESS;
                }
                if (APR_SUCCESS == status) {
                    /* short circuit, all good */
                    val = trim(val);
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
            else {

                char *end;

                /* parse index, is it the largest so far? */

                apr_int64_t order = apr_strtoi64(val, &end, 10);
                if (end[0] || errno == ERANGE) {
                    apr_file_printf(ds->err, "argument '%s': '%s' is not a valid index, ignoring.\n",
                            apr_pescape_echo(ds->pool, pair->key, 1),
                            apr_pescape_echo(ds->pool, val, 1));
                    /* ignore and loop round */
                }
                else if (order == APR_INT64_MAX) {
                    apr_file_printf(ds->err, "argument '%s': existing index '%s' is too big.\n",
                            apr_pescape_echo(ds->pool, pair->key, 1),
                            apr_pescape_echo(ds->pool, val, 1));
                    return APR_EGENERAL;
                }

                /* nothing counts until we find a match */
                if (order == ind) {
                    found = 1;
                }

                if (order >= ind) {

                    device_file_t *file, *link;

                    order++;

                    val = apr_psprintf(ds->pool, "%" APR_INT64_T_FMT, order);

                    if (APR_SUCCESS
                            != (status = apr_filepath_merge(&path, "..",
                                    indexpath, APR_FILEPATH_NOTABSOLUTE, pool))) {
                        apr_file_printf(ds->err, "cannot merge option set key '%s': %pm\n", pair->key,
                                &status);
                        return status;
                    }

                    if (APR_SUCCESS
                            != (status = apr_filepath_merge(&linkpath, "..",
                                    val, APR_FILEPATH_NOTABSOLUTE, pool))) {
                        apr_file_printf(ds->err, "cannot merge option set key '%s': %pm\n", pair->key,
                                &status);
                        return status;
                    }

                    /* add index */
                    file = apr_array_push(tfiles);
                    file->type = APR_REG;
                    file->order = order;

                    file->dest = path;
                    file->template = apr_pstrcat(ds->pool, file->dest, ".XXXXXX", NULL);
                    file->key = pair->key;
                    file->val = val;
                    file->index = pair->index;

                    if (pair->index == DEVICE_IS_INDEXED) {

                        /* add symlink */
                        link = apr_array_push(tfiles);
                        link->type = APR_LNK;
                        link->order = order;

                        link->dest = linkpath;
                        link->key = pair->key;
                        link->val = apr_pstrdup(ds->pool, dirent.name);
                        link->index = DEVICE_IS_NORMAL;
                    }

                }
            }

            apr_pool_destroy(pool);

            break;
        }
        default:
            break;
        }

    } while (1);

    apr_dir_close(thedir);

    if (APR_SUCCESS == status) {
        /* short circuit, all good */
    }
    else if (APR_STATUS_IS_ENOENT(status)) {
        status = APR_SUCCESS;
    }
    else {
        apr_file_printf(ds->err, "cannot read indexes: %pm\n",
                &status);
        return status;
    }

    if (found) {

        /* sort tfiles large to small so reindex doesn't stomp on files */
        qsort(tfiles->elts, tfiles->nelts, tfiles->elt_size, files_desc);

        apr_array_cat(files, tfiles);
        tfiles = files;

        /* suppress the unique check */
        pair->unique = DEVICE_IS_REPEATED;
    }

    if (option) {
        *option = apr_psprintf(ds->pool, "%" APR_INT64_T_FMT, ind);
    }
    return APR_SUCCESS;
}

/*
 * Port is an integer between 0 and 65535 inclusive.
 */
static apr_status_t device_parse_port(device_set_t *ds, device_pair_t *pair,
        const char *arg, const char **option)
{
    char *end;

    if (!arg) {
        apr_file_printf(ds->err, "argument '%s': is empty.\n",
                apr_pescape_echo(ds->pool, pair->key, 1));
        return APR_INCOMPLETE;
    }

    if (pair->optional == DEVICE_IS_REQUIRED && !arg[0]) {
        apr_file_printf(ds->err, "'%s' is required\n", pair->key);
        return APR_EGENERAL;
    }
    else if (!arg[0]) {
        if (option) {
            option[0] = NULL;
        }
        return APR_SUCCESS;
    }

    apr_int64_t port = apr_strtoi64(arg, &end, 10);
    if (end[0] || port < DEVICE_PORT_MIN || port > DEVICE_PORT_MAX) {
        apr_file_printf(ds->err, "argument '%s': '%s' is not a valid port.\n",
                apr_pescape_echo(ds->pool, pair->key, 1),
                apr_pescape_echo(ds->pool, arg, 1));
        return APR_EINVAL;
    }
    if (option) {
        option[0] = arg;
    }
    return APR_SUCCESS;
}

/*
 * Port is an integer between 1025 and 49151 inclusive.
 */
static apr_status_t device_parse_unprivileged_port(device_set_t *ds,
        device_pair_t *pair, const char *arg, const char **option)
{
    char *end;

    if (!arg) {
        apr_file_printf(ds->err, "argument '%s': is empty.\n",
                apr_pescape_echo(ds->pool, pair->key, 1));
        return APR_INCOMPLETE;
    }

    if (pair->optional == DEVICE_IS_REQUIRED && !arg[0]) {
        apr_file_printf(ds->err, "'%s' is required\n", pair->key);
        return APR_EGENERAL;
    }
    else if (!arg[0]) {
        if (option) {
            option[0] = NULL;
        }
        return APR_SUCCESS;
    }

    apr_int64_t port = apr_strtoi64(arg, &end, 10);
    if (end[0] || port < DEVICE_PORT_UNPRIVILEGED_MIN || port > DEVICE_PORT_UNPRIVILEGED_MAX) {
        apr_file_printf(ds->err, "argument '%s': '%s' is not a valid unprivileged port.\n",
                apr_pescape_echo(ds->pool, pair->key, 1),
                apr_pescape_echo(ds->pool, arg, 1));
        return APR_EINVAL;
    }
    if (option) {
        option[0] = arg;
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
        const char *arg, const char **option)
{
    int len = 0;

    if (!arg) {
        apr_file_printf(ds->err, "argument '%s': is empty.\n",
                apr_pescape_echo(ds->pool, pair->key, 1));
        return APR_INCOMPLETE;
    }

    if (pair->optional == DEVICE_IS_REQUIRED && !arg[0]) {
        apr_file_printf(ds->err, "'%s' is required\n", pair->key);
        return APR_EGENERAL;
    }
    else if (!arg[0]) {
        if (option) {
            option[0] = NULL;
        }
        return APR_SUCCESS;
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

    if (option) {
        option[0] = arg;
    }

    return APR_SUCCESS;
}

/*
 * Fully Qualified Domain Name is a series of hostnames (defined above),
 * separated by dots '.', and with a length no larger than 253 characters
 * inclusive.
 */
static apr_status_t device_parse_fqdn(device_set_t *ds, device_pair_t *pair,
        const char *arg, const char **option)
{
    int len = 0, hlen = 0;

    if (!arg) {
        apr_file_printf(ds->err, "argument '%s': is empty.\n",
                apr_pescape_echo(ds->pool, pair->key, 1));
        return APR_INCOMPLETE;
    }

    if (pair->optional == DEVICE_IS_REQUIRED && !arg[0]) {
        apr_file_printf(ds->err, "'%s' is required\n", pair->key);
        return APR_EGENERAL;
    }
    else if (!arg[0]) {
        if (option) {
            option[0] = NULL;
        }
        return APR_SUCCESS;
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

    if (option) {
        option[0] = arg;
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

    if (pair->optional == DEVICE_IS_OPTIONAL) {
        if (pair->unset) {
            none = pair->unset;
        }
        else {
            none = DEVICE_SELECT_NONE;
        }
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
            apr_file_printf(ds->err, "cannot seek start of options '%s': %pm\n", pair->key,
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
                    strcpy(buffer, none);
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
                            pair->optional == DEVICE_IS_OPTIONAL ? "-" : "*",
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
    char *result = NULL;
    apr_int64_t bytes;

    apr_array_header_t *possibles = apr_array_make(ds->pool, 10, sizeof(char *));

    if (!arg) {
        apr_file_printf(ds->err, "argument '%s': is empty.\n",
                apr_pescape_echo(ds->pool, pair->key, 1));
        return APR_INCOMPLETE;
    }

    if (pair->optional == DEVICE_IS_REQUIRED && !arg[0]) {
        apr_file_printf(ds->err, "'%s' is required\n", pair->key);
        return APR_EGENERAL;
    }
    else if (!arg[0]) {
        if (option) {
            option[0] = NULL;
        }
        return APR_SUCCESS;
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
                    pair->optional == DEVICE_IS_OPTIONAL ? '-' : '*', \
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
        const char *arg, apr_array_header_t *options, const char **option,
        const char **link)
{
    const char *none = NULL, *dirname, *basename;
    apr_status_t status;
    apr_size_t baselen;

    apr_array_header_t *possibles = apr_array_make(ds->pool, 10, sizeof(char *));

    int i;

    if (option) {
        option[0] = NULL; /* until further notice */
    }

    if (pair->optional == DEVICE_IS_OPTIONAL) {
        if (pair->unset) {
            none = pair->unset;
        }
        else {
            none = DEVICE_SYMLINK_NONE;
        }
    }

    /* find the base path, up to depth */
    if (none && !strcmp(arg, none)) {
        basename = arg;
        dirname = NULL;
    }

    else if (pair->s.symlink_recursive) {

        if (arg[0] != '/') {
            apr_file_printf(ds->err, "'%s' must start with a '/'.\n", pair->key);
            return APR_EINVAL;
        }

        else {
            basename = strrchr(arg + 1, '/');
            if (!basename) {
                dirname = "";
                basename = arg + 1;
            }
            else {
                dirname = apr_pstrndup(ds->pool, arg + 1, basename - arg - 1);
                basename++;
            }
        }

    }
    else {

        if (arg[0] == '/') {
            apr_file_printf(ds->err, "'%s' must not start with a '/'.\n", pair->key);
            return APR_EINVAL;
        }

        basename = arg;
        dirname = NULL;

    }

    baselen = strlen(basename);

    if (!pair->s.bases) {
        apr_file_printf(ds->err, "no base directory specified for '%s'\n", pair->key);
        return APR_EGENERAL;
    }

    for (i = 0; i < pair->s.bases->nelts; i++) {

        apr_dir_t *thedir;
        apr_finfo_t dirent;

        char *base = APR_ARRAY_IDX(pair->s.bases, i, char *);

        if (dirname && dirname[0] && APR_SUCCESS
                != (status = apr_filepath_merge(&base, base,
                        dirname,
                        APR_FILEPATH_SECUREROOT, ds->pool))) {
            apr_file_printf(ds->err, "cannot merge directory for '%s': %pm\n", pair->key,
                    &status);
            return status;
        }

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

#if HAVE_SELINUX_SELINUX_H
                /* check selinux context */
                if (pair->s.symlink_context_type) {
                    char *raw = NULL;
                    char *target;
                    int len;

                    if (APR_SUCCESS
                            != (status = apr_filepath_merge(&target, base,
                                    dirent.name,
                                    APR_FILEPATH_NATIVE, ds->pool))) {
                        apr_file_printf(ds->err, "cannot merge for context '%s': %pm\n", pair->key,
                                &status);
                        continue;
                    }

                    len = getfilecon(target, &raw);

                    if (len < 0) {

                        switch (errno) {
                        case ENOTSUP:
                            /* not supported - allow through */
                            break;
                        default:
                            /* all other errors - ignore file */
                            continue;
                        }

                    }
                    else {
                        context_t con = context_new(raw);

                        const char *type = context_type_get(con);

                        if (strcmp(pair->s.symlink_context_type, type)) {
                            context_free(con);
                            freecon(raw);
                            /* no match - ignore file */
                            continue;
                        }

                        context_free(con);
                        freecon(raw);
                    }
                }
#endif

                /* suffixes? */
                if (pair->s.symlink_suffix) {
                    int len = strlen(dirent.name);
                    if (len < pair->s.symlink_suffix_len
                            || strcmp(pair->s.symlink_suffix,
                                    dirent.name + len - pair->s.symlink_suffix_len)) {
                        continue;
                    }
                    name = apr_pstrndup(ds->pool, dirent.name,
                            len - pair->s.symlink_suffix_len);
                }
                else {
                    name = apr_pstrdup(ds->pool, dirent.name);
                }
            }

            switch (dirent.filetype) {
            case APR_LNK:
            case APR_REG:
            case APR_DIR: {

                int exact = (0 == strcmp(basename, name));

                const char *path;

                if (none) {
                    path = none;
                }
                else if (dirname) {
                    if (dirname[0]) {
                        path = apr_pstrcat(ds->pool, "/", dirname, "/", name, NULL);
                    }
                    else {
                        path = apr_pstrcat(ds->pool, "/", name, NULL);
                    }
                }
                else {
                    path = name;
                }

                possible = apr_array_push(possibles);
                possible[0] = name;

                if (!strncmp(basename, name, baselen)) {

                    const char **opt;

                    if (exact) {
                        apr_array_clear(options);
                    }

                    opt = apr_array_push(options);
                    opt[0] = apr_pstrcat(ds->pool,
                            pair->optional == DEVICE_IS_OPTIONAL ? "-" : "*",
                            device_pescape_shell(ds->pool, pair->key), "=",
                            device_pescape_shell(ds->pool, path),
                            NULL);

                    if (option) {

                        char *target;

                        if (none) {
                            option[0] = NULL;
                            link[0] = NULL;
                        }
                        else if (APR_SUCCESS
                                != (status = apr_filepath_merge(&target, base,
                                        apr_pstrcat(ds->pool, name, pair->suffix, NULL),
                                        APR_FILEPATH_NATIVE, ds->pool))) {
                            apr_file_printf(ds->err, "cannot merge links '%s': %pm\n", pair->key,
                                    &status);
                        }
                        else {
                            option[0] = apr_pstrdup(ds->pool, name);
                            link[0] = target;
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
static apr_status_t device_parse_uint64(device_set_t *ds, const char *arg,
        apr_uint64_t *result)
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

    if (!strcmp(arg, "min")) {
        bytes = 0;
    }
    else if (!strcmp(arg, "max")) {
        bytes = APR_INT64_MAX;
    }
    else {

        bytes = apr_strtoi64(arg, &end, 10);

        if (end[0]) {
            apr_file_printf(ds->err, "number '%s' is not a number.\n",
                    apr_pescape_echo(ds->pool, arg, 1));
            return APR_EINVAL;
        }

    }

    *result = bytes;

    return APR_SUCCESS;
}

/*
 * Parse a signed integer.
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

    if (!strcmp(arg, "min")) {
        bytes = 0;
    }
    else if (!strcmp(arg, "max")) {
        bytes = APR_INT64_MAX;
    }
    else {

        bytes = apr_strtoi64(arg, &end, 10);

        if (end[0]) {
            apr_file_printf(ds->err, "number '%s' is not a number.\n",
                    apr_pescape_echo(ds->pool, arg, 1));
            return APR_EINVAL;
        }

    }

    *result = bytes;

    return APR_SUCCESS;
}

/*
 * Parse a signed hex integer.
 */
static apr_status_t device_parse_hex64(device_set_t *ds, const char *arg,
        apr_uint64_t *result)
{
    char *end;
    apr_uint64_t hex;

    if (!arg || !arg[0]) {
        apr_file_printf(ds->err, "number is empty.\n");
        return APR_INCOMPLETE;
    }

    if (!strcmp(arg, "min")) {
        hex = 0;
    }
    else if (!strcmp(arg, "max")) {
        hex = APR_UINT64_MAX;
    }
    else {

        hex = device_strtoui64(arg, &end, 16);

        if (end[0]) {
            apr_file_printf(ds->err, "number '%s' is not a hex number.\n",
                    apr_pescape_echo(ds->pool, arg, 1));
            return APR_EINVAL;
        }

    }

    *result = hex;

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

    if (!arg) {
        apr_file_printf(ds->err, "argument '%s': is empty.\n",
                apr_pescape_echo(ds->pool, pair->key, 1));
        return APR_INCOMPLETE;
    }

    if (pair->optional == DEVICE_IS_REQUIRED && !arg[0]) {
        apr_file_printf(ds->err, "'%s' is required\n", pair->key);
        return APR_EGENERAL;
    }
    else if (!arg[0]) {
        if (translated) {
            translated[0] = NULL;
        }
        return APR_SUCCESS;
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

    if (!arg) {
        apr_file_printf(ds->err, "argument '%s': is empty.\n",
                apr_pescape_echo(ds->pool, pair->key, 1));
        return APR_INCOMPLETE;
    }

    if (pair->optional == DEVICE_IS_REQUIRED && !arg[0]) {
        apr_file_printf(ds->err, "'%s' is required\n", pair->key);
        return APR_EGENERAL;
    }
    else if (!arg[0]) {
        if (translated) {
            translated[0] = NULL;
        }
        return APR_SUCCESS;
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

    if (pair->optional == DEVICE_IS_OPTIONAL) {
        if (pair->unset) {
            none = pair->unset;
        }
        else {
            none = DEVICE_USER_NONE;
        }
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
                        pair->optional == DEVICE_IS_OPTIONAL ? "-" : "*",
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
                                pair->optional == DEVICE_IS_OPTIONAL ? "-" : "*",
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

    if (pair->optional == DEVICE_IS_REQUIRED && !arglen) {
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

        if (option) {
            option[0] = arg;
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

    /* we should never reach here */
    return APR_EGENERAL;
}

/**
 * Relation is a name that will be linked to a given file beneath directories at
 * a target path.
 */
static apr_status_t device_parse_relation(device_set_t *ds, device_pair_t *pair,
        const char *arg, apr_array_header_t *options, const char **option,
        const char **link)
{
    const char *none = NULL;
    apr_status_t status;
    apr_size_t arglen = arg ? strlen(arg) : 0;

    apr_pool_t *pool;

    apr_array_header_t *possibles = apr_array_make(ds->pool, 10, sizeof(char *));

    int i;

    if (option) {
        option[0] = NULL; /* until further notice */
    }

    if (!pair->r.relation_name) {
        apr_file_printf(ds->err, "no relation name specified for '%s'\n", pair->key);
        return APR_EGENERAL;
    }

    if (!pair->r.bases) {
        apr_file_printf(ds->err, "no base directory specified for '%s'\n", pair->key);
        return APR_EGENERAL;
    }

    if (pair->optional == DEVICE_IS_OPTIONAL) {
        if (pair->unset) {
            none = pair->unset;
        }
        else {
            none = DEVICE_RELATION_NONE;
        }
    }

    apr_pool_create(&pool, ds->pool);

    for (i = 0; i < pair->r.bases->nelts; i++) {

        apr_dir_t *thedir;
        apr_finfo_t dirent;

        const char *base = APR_ARRAY_IDX(pair->r.bases, i, const char *);

        if ((status = apr_dir_open(&thedir, base, ds->pool)) != APR_SUCCESS) {
            /* could not open directory, skip */
            continue;
        }

        do {
            const char **possible;
            char *name = NULL;
            char *keypath;

            int exact;

            apr_pool_clear(pool);

            if (none) {

                name = apr_pstrdup(ds->pool, none);
                keypath = NULL;

            } else {

                apr_file_t *in;

                const char *keyname;
                char *keyfile;

                apr_off_t end = 0, start = 0;

                status = apr_dir_read(&dirent,
                        APR_FINFO_TYPE | APR_FINFO_NAME | APR_FINFO_WPROT, thedir);
                if (APR_STATUS_IS_INCOMPLETE(status)) {
                    continue; /* ignore un-stat()able files */
                } else if (status != APR_SUCCESS) {
                    break;
                }

                /* hidden files are ignored */
                if (dirent.name[0] == '.' || dirent.filetype != APR_DIR) {
                    continue;
                }

                keyname = apr_pstrcat(pool, pair->r.relation_name, pair->r.relation_suffix, NULL);
                if (APR_SUCCESS
                        != (status = apr_filepath_merge(&keypath, base, dirent.name,
                                APR_FILEPATH_NATIVE, pool))) {
                    apr_file_printf(ds->err, "cannot merge option set key '%s' (base): %pm\n", pair->key,
                            &status);
                }
                else if (pair->r.relation_prefix && APR_SUCCESS
                        != (status = apr_filepath_merge(&keypath, keypath,
                                pair->r.relation_prefix, APR_FILEPATH_NATIVE, pool))) {
                    apr_file_printf(ds->err, "cannot merge option set key '%s' (prefix): %pm\n", pair->key,
                            &status);
                }
                else if (APR_SUCCESS
                        != (status = apr_filepath_merge(&keyfile, keypath,
                                keyname, APR_FILEPATH_NATIVE, pool))) {
                    apr_file_printf(ds->err, "cannot merge option set key '%s' (name): %pm\n", pair->key,
                            &status);
                }

                /* open the key */
                else if (APR_SUCCESS
                        != (status = apr_file_open(&in, keyfile, APR_FOPEN_READ,
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
                    apr_file_printf(ds->err, "cannot seek start of option set '%s': %pm\n", pair->key,
                            &status);
                }

                else {
                    int size = end + 1;
                    name = apr_palloc(pool, size);
                    name[end] = 0;

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
                    continue;
                }

            }

            exact = (0 == strcmp(arg, name));

            possible = apr_array_push(possibles);
            possible[0] = apr_pstrdup(possibles->pool, name);

            if (!strncmp(arg, name, arglen)) {

                const char **opt;

                if (exact) {
                    apr_array_clear(options);
                }

                opt = apr_array_push(options);
                opt[0] = apr_pstrcat(ds->pool,
                        pair->optional == DEVICE_IS_OPTIONAL ? "-" : "*",
                        device_pescape_shell(ds->pool, pair->key), "=",
                        device_pescape_shell(ds->pool, name),
                        NULL);

                if (option) {

                    if (none) {
                        option[0] = NULL;
                        link[0] = NULL;
                    }
                    else {
                        option[0] = apr_pstrdup(ds->pool, name);
                        link[0] = apr_pstrdup(ds->pool, keypath);
                    }

                }
            }

            if (exact) {

                /* exact matches short circuit */
                apr_dir_close(thedir);

                goto done;
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

        status = APR_SUCCESS;

        if (option) {
            if (options->nelts == 1) {
                /* all ok */
            }
            else {
                device_error_possibles(ds, pair->key, possibles);

                status = APR_INCOMPLETE;
            }
        }
    }
    else {
        apr_file_printf(ds->err, "cannot read option '%s': %pm\n", pair->key,
                &status);
    }

    apr_pool_destroy(pool);

    return status;
}

/**
 * Polar is a string containing either the value "yes" or "no".
 */
static apr_status_t device_parse_polar(device_set_t *ds, device_pair_t *pair,
        const char *arg, apr_array_header_t *options, const char **option)
{
    apr_size_t arglen = arg ? strlen(arg) : 0;

    const char **opt;

    if (option) {
        option[0] = NULL; /* until further notice */
    }

    if (!strncmp(arg, "yes", arglen)) {

        if (!strcmp(arg, "yes")) {
            apr_array_clear(options);
        }

        opt = apr_array_push(options);
        opt[0] = apr_pstrcat(ds->pool,
                pair->optional == DEVICE_IS_OPTIONAL ? "-" : "*",
                device_pescape_shell(ds->pool, pair->key), "=",
                device_pescape_shell(ds->pool, "yes"),
                NULL);

        if (option) {
            option[0] = ""; /* file exists and is empty */
        }
    }

    if (!strncmp(arg, "no", arglen)) {

        if (!strcmp(arg, "no")) {
            apr_array_clear(options);
        }

        opt = apr_array_push(options);
        opt[0] = apr_pstrcat(ds->pool,
                pair->optional == DEVICE_IS_OPTIONAL ? "-" : "*",
                device_pescape_shell(ds->pool, pair->key), "=",
                device_pescape_shell(ds->pool, "no"),
                NULL);

        if (option) {
            option[0] = NULL; /* file does not exist */
        }
    }

    if (option) {
        if (options->nelts == 1) {
            /* all ok */
        }
        else {
            apr_file_printf(ds->err, "%s: must be 'yes' or 'no'.\n",
                apr_pescape_echo(ds->pool, arg, 1));
            return APR_INCOMPLETE;
        }
    }

    return APR_SUCCESS;
}

/**
 * Switch is a string containing either the value "on" or "off".
 */
static apr_status_t device_parse_switch(device_set_t *ds, device_pair_t *pair,
        const char *arg, apr_array_header_t *options, const char **option)
{
    apr_size_t arglen = arg ? strlen(arg) : 0;

    const char **opt;

    if (option) {
        option[0] = NULL; /* until further notice */
    }

    if (!strncmp(arg, "on", arglen)) {

        if (!strcmp(arg, "on")) {
            apr_array_clear(options);
        }

        opt = apr_array_push(options);
        opt[0] = apr_pstrcat(ds->pool,
                pair->optional == DEVICE_IS_OPTIONAL ? "-" : "*",
                device_pescape_shell(ds->pool, pair->key), "=",
                device_pescape_shell(ds->pool, "on"),
                NULL);

        if (option) {
            option[0] = ""; /* file exists and is empty */
        }
    }

    if (!strncmp(arg, "off", arglen)) {

        if (!strcmp(arg, "off")) {
            apr_array_clear(options);
        }

        opt = apr_array_push(options);
        opt[0] = apr_pstrcat(ds->pool,
                pair->optional == DEVICE_IS_OPTIONAL ? "-" : "*",
                device_pescape_shell(ds->pool, pair->key), "=",
                device_pescape_shell(ds->pool, "off"),
                NULL);

        if (option) {
            option[0] = NULL; /* file does not exist */
        }
    }

    if (option) {
        if (options->nelts == 1) {
            /* all ok */
        }
        else {
            apr_file_printf(ds->err, "%s: must be 'on' or 'off'.\n",
                apr_pescape_echo(ds->pool, arg, 1));
            return APR_INCOMPLETE;
        }
    }

    return APR_SUCCESS;
}

/*
 * Integer is a signed 64 bit whole number.
 */
static apr_status_t device_parse_integer(device_set_t *ds, device_pair_t *pair,
        const char *arg, apr_array_header_t *options, const char **option)
{
    apr_int64_t result;

    apr_status_t status;

    if (!arg) {
        apr_file_printf(ds->err, "argument '%s': is empty.\n",
                apr_pescape_echo(ds->pool, pair->key, 1));
        return APR_INCOMPLETE;
    }

    if (pair->optional == DEVICE_IS_REQUIRED && !arg[0]) {
        apr_file_printf(ds->err, "'%s' is required\n", pair->key);
        return APR_EGENERAL;
    }
    else if (!arg[0]) {
        if (option) {
            option[0] = NULL;
        }
        return APR_SUCCESS;
    }

    status = device_parse_int64(ds, arg, &result);

    if (APR_SUCCESS == status) {

        if (!strcmp(arg, "min")) {
            result = pair->i.min;
        }
        else if (!strcmp(arg, "max")) {
            result = pair->i.max;
        }

        if (result < pair->i.min || result > pair->i.max) {
            apr_file_printf(ds->err, "%s: must be between %"
                APR_INT64_T_FMT " and %" APR_INT64_T_FMT ".\n",
                apr_pescape_echo(ds->pool, arg, 1),
                    pair->i.min, pair->i.max);
            return APR_ERANGE;
        }

        if (option) {
            option[0] = apr_ltoa(ds->pool, result);
        }
    }

    return status;
}

/*
 * Hex is a signed 64 bit base 16 whole number.
 */
static apr_status_t device_parse_hex(device_set_t *ds, device_pair_t *pair,
        const char *arg, apr_array_header_t *options, const char **option)
{
    apr_uint64_t result;

    apr_status_t status;

    if (!arg) {
        apr_file_printf(ds->err, "argument '%s': is empty.\n",
                apr_pescape_echo(ds->pool, pair->key, 1));
        return APR_INCOMPLETE;
    }

    if (pair->optional == DEVICE_IS_REQUIRED && !arg[0]) {
        apr_file_printf(ds->err, "'%s' is required\n", pair->key);
        return APR_EGENERAL;
    }
    else if (!arg[0]) {
        if (option) {
            option[0] = NULL;
        }
        return APR_SUCCESS;
    }

    status = device_parse_hex64(ds, arg, &result);

    if (APR_SUCCESS == status) {

        if (!strcmp(arg, "min")) {
            result = pair->h.min;
        }
        else if (!strcmp(arg, "max")) {
            result = pair->h.max;
        }

        if (result < pair->h.min || result > pair->h.max) {
            apr_file_printf(ds->err, "%s: must be between %"
                APR_UINT64_T_HEX_FMT " and %" APR_UINT64_T_HEX_FMT ".\n",
                apr_pescape_echo(ds->pool, arg, 1),
                    pair->i.min, pair->i.max);
            return APR_ERANGE;
        }

        if (option) {

            char fmt[16] = "%.*" APR_UINT64_T_HEX_FMT;

            if (pair->h.cs == DEVICE_IS_UPPER) {
                char *x = strchr(fmt, 'x');
                if (x) {
                    *x = 'X';
                }
            }

            option[0] = apr_psprintf(ds->pool, fmt, pair->h.width, result);
        }
    }

    return status;
}

/*
 * Text is a string to be converted to the defined character set.
 */
static apr_status_t device_parse_text(device_set_t *ds, device_pair_t *pair,
        const char *arg, apr_array_header_t *options, const char **option)
{
    char *inbuf, *outbuf;
    apr_size_t inbytesleft, outbytesleft, nchars, outlen;
    apr_status_t status = APR_SUCCESS;

    char *out;

    const char *from = nl_langinfo(CODESET);

    iconv_t ic = iconv_open(pair->t.format, from);

    if ((iconv_t)(-1) == ic) {
        status = errno;
        apr_file_printf(ds->err, "%s: cannot convert '%s' to '%s': %pm\n",
                device_pescape_shell(ds->pool, pair->key), from, pair->t.format,
                &status);
        return status;
    }

    if (!arg) {
        apr_file_printf(ds->err, "argument '%s': is empty.\n",
                apr_pescape_echo(ds->pool, pair->key, 1));
        return APR_INCOMPLETE;
    }

    if (pair->optional == DEVICE_IS_REQUIRED && !arg[0]) {
        apr_file_printf(ds->err, "'%s' is required\n", pair->key);
        return APR_EGENERAL;
    }
    else if (!arg[0]) {
        if (option) {
            option[0] = NULL;
        }
        return APR_SUCCESS;
    }

    inbuf = (char *)arg;
    inbytesleft = strlen(arg);
    outbytesleft = 0;

    out = NULL;
    outlen = 0;

    do {

        out = realloc(out, outlen + 256);
        if (!out) {
            iconv_close(ic);
            return APR_ENOMEM;
        }

        outbuf = out + outlen - outbytesleft;
        outlen += 256;
        outbytesleft += 256;

        nchars = iconv(ic, &inbuf, &inbytesleft, &outbuf, &outbytesleft);

    } while (nchars == (apr_size_t)-1 && errno == E2BIG);

    if (nchars == (apr_size_t) -1) {
        status = errno;
        if (errno == EILSEQ) {
            apr_file_printf(ds->err, "%s: contains an invalid '%s' character: %pm\n",
                    device_pescape_shell(ds->pool, pair->key), from, &status);
            goto end;
        } else if (errno == EINVAL) {
            apr_file_printf(ds->err, "%s: ends with a truncated '%s' character: %pm\n",
                    device_pescape_shell(ds->pool, pair->key), from, &status);
            goto end;
        } else {
            apr_file_printf(ds->err, "%s: cannot convert a '%s' character: %pm\n",
                    device_pescape_shell(ds->pool, pair->key), from, &status);
            goto end;
        }
    }

    outlen -= outbytesleft;

    if (outlen < pair->t.min) {
        apr_file_printf(ds->err, "%s: text is too short (%" APR_SIZE_T_FMT " converted bytes)\n",
                device_pescape_shell(ds->pool, pair->key), outlen);
        status = APR_ERANGE;
        goto end;
    }
    else if (outlen > pair->t.max) {
        apr_file_printf(ds->err, "%s: text is too long (%" APR_SIZE_T_FMT " converted bytes)\n",
                device_pescape_shell(ds->pool, pair->key), outlen);
        status = APR_ERANGE;
        goto end;
    }

    if (option) {
        *option = apr_pstrndup(ds->pool, out, outlen);
    }

end:

    free(out);

    iconv_close(ic);

    return status;
}

typedef struct device_url_path_state_t {
    unsigned int abempty:1;
    unsigned int absolute:1;
    unsigned int noscheme:1;
    unsigned int rootless:1;
    unsigned int empty:1;
    unsigned int percent:2;
    int segments;
    int last_slash;
} device_url_path_state_t;

/*
 * URL path is a URL encoded string limited by section 3.3 of RFC3986.
 */
static apr_status_t device_parse_url_path_ex(device_set_t *ds, device_pair_t *pair,
        const char *arg, device_url_path_state_t *cur, apr_uint64_t max)
{
    apr_size_t len = 0;

    /* we begin with all path types possible, and eliminate as we go */
    cur->abempty = 1;
    cur->absolute = 1;
    cur->noscheme = 1;
    cur->rootless = 1;
    cur->empty = 1;
    cur->segments = 0;
    cur->last_slash = 0;
    cur->percent = 0;

    if (!arg) {
        apr_file_printf(ds->err, "argument '%s': is missing.\n",
                apr_pescape_echo(ds->pool, pair->key, 1));
        return APR_INCOMPLETE;
    }

    while (1) {
        char c = arg[len++];

        /* not too long? */
        if (len >= max) {
            /* not ok */
            apr_file_printf(ds->err, "argument '%s': '%s' is too long (%" APR_SIZE_T_FMT " character limit).\n",
                    apr_pescape_echo(ds->pool, pair->key, 1),
                    apr_pescape_echo(ds->pool,
                            apr_pstrcat(ds->pool,
                                    apr_pstrndup(ds->pool, arg, 64), "...",
                                    NULL), 1), max);
            return APR_EINVAL;
        }

        /* hexdig expected */
        if (cur->percent) {

            /* but only two hexdigs */
            if (cur->percent == 3) {
                cur->percent = 0;
                /* drop through */
            }

            /* hexdig is good */
            else if ((c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || (c >= '0' && c <= '9')) {
                cur->percent++;
                continue;
            }

            /* not hexdig is bad */
            else {
                apr_file_printf(ds->err, "argument '%s': percent encoding cut short.\n",
                    apr_pescape_echo(ds->pool, pair->key, 1));
                return APR_EINVAL;
            }
        }

        /* end of path */
        if (c == 0) {
            if (len == 1) {
                /* empty path detected */
                cur->absolute = 0;
                cur->noscheme = 0;
                cur->rootless = 0;
            }

            break;
        }

        /* slash detected */
        if (c == '/') {
            if (len == 1) {
                /* absolute path detected */
                cur->noscheme = 0;
                cur->rootless = 0;
                cur->empty = 0;
            }

            if (len == 2 && cur->last_slash == 1) {
                /* double slash detected */
                apr_file_printf(ds->err, "argument '%s': second character cannot be a slash.\n",
                        apr_pescape_echo(ds->pool, pair->key, 1));
                return APR_EINVAL;
            }

            cur->segments++;
            cur->last_slash = len;
            continue;
        }

        /* unreserved detected */
        /* unreserved  = ALPHA / DIGIT / "-" / "." / "_" / "~" */
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' || c == '~') {

            if (len == 1) {
                cur->absolute = 0;
                cur->abempty = 0;
                cur->empty = 0;
            }

            /* ok */
            continue;
        }

        /* pct-encoded detected */
        if (c == '%') {

            if (len == 1) {
                cur->absolute = 0;
                cur->abempty = 0;
                cur->empty = 0;
            }

            cur->percent++;
            continue;
        }

        /* sub-delims detected */
        if (c == '!' || c == '$' || c == '&' || c == '\'' || c == '(' || c == ')'
                || c == '*' || c == '+' || c == ',' || c == ';' || c == '=') {

            if (len == 1) {
                cur->absolute = 0;
                cur->abempty = 0;
                cur->empty = 0;
            }

            /* ok */
            continue;
        }

        /* colon detected */
        if (c == ':') {

            if (len == 1) {
                cur->absolute = 0;
                cur->abempty = 0;
                cur->empty = 0;
            }

            if (cur->segments == 0) {
                cur->noscheme = 0;
            }

            continue;
        }

        /* "@" detected */
        if (c == '@') {

            if (len == 1) {
                cur->absolute = 0;
                cur->abempty = 0;
                cur->empty = 0;
            }

            /* ok */
            continue;
        }

        /* anything else is a no */
        else {
            apr_file_printf(ds->err, "argument '%s': '%c' is an invalid character.\n",
                    apr_pescape_echo(ds->pool, pair->key, 1), c);
            return APR_EINVAL;
        }

    }

    return APR_SUCCESS;
}

static apr_status_t device_parse_url_path(device_set_t *ds, device_pair_t *pair,
        const char *arg, apr_array_header_t *options, const char **option)
{
    device_url_path_state_t cur = { 0 };
    apr_status_t status;

    if (!arg) {
        apr_file_printf(ds->err, "argument '%s': is empty.\n",
                apr_pescape_echo(ds->pool, pair->key, 1));
        return APR_INCOMPLETE;
    }

    if (pair->optional == DEVICE_IS_REQUIRED && !arg[0]) {
        apr_file_printf(ds->err, "'%s' is required\n", pair->key);
        return APR_EGENERAL;
    }
    else if (!arg[0]) {
        if (option) {
            option[0] = NULL;
        }
        return APR_SUCCESS;
    }

    status = device_parse_url_path_ex(ds, pair, arg, &cur, pair->up.max);
    if (APR_SUCCESS != status) {
        return status;
    }

    if (option) {
        option[0] = arg;
    }

    return APR_SUCCESS;
}

static apr_status_t device_parse_url_path_abempty(device_set_t *ds, device_pair_t *pair,
        const char *arg, apr_array_header_t *options, const char **option)
{
    device_url_path_state_t cur = { 0 };
    apr_status_t status;

    if (!arg) {
        apr_file_printf(ds->err, "argument '%s': is empty.\n",
                apr_pescape_echo(ds->pool, pair->key, 1));
        return APR_INCOMPLETE;
    }

    if (pair->optional == DEVICE_IS_REQUIRED && !arg[0]) {
        apr_file_printf(ds->err, "'%s' is required\n", pair->key);
        return APR_EGENERAL;
    }
    else if (!arg[0]) {
        if (option) {
            option[0] = NULL;
        }
        return APR_SUCCESS;
    }

    status = device_parse_url_path_ex(ds, pair, arg, &cur, pair->up.max);
    if (APR_SUCCESS != status) {
        return status;
    }

    if (!cur.abempty) {
        apr_file_printf(ds->err, "argument '%s': path not absolute or empty.\n",
                apr_pescape_echo(ds->pool, pair->key, 1));
        return APR_EINVAL;
    }

    if (option) {
        option[0] = arg;
    }

    return APR_SUCCESS;
}

static apr_status_t device_parse_url_path_absolute(device_set_t *ds, device_pair_t *pair,
        const char *arg, apr_array_header_t *options, const char **option)
{
    device_url_path_state_t cur = { 0 };
    apr_status_t status;

    if (!arg) {
        apr_file_printf(ds->err, "argument '%s': is empty.\n",
                apr_pescape_echo(ds->pool, pair->key, 1));
        return APR_INCOMPLETE;
    }

    if (pair->optional == DEVICE_IS_REQUIRED && !arg[0]) {
        apr_file_printf(ds->err, "'%s' is required\n", pair->key);
        return APR_EGENERAL;
    }
    else if (!arg[0]) {
        if (option) {
            option[0] = NULL;
        }
        return APR_SUCCESS;
    }

    status = device_parse_url_path_ex(ds, pair, arg, &cur, pair->up.max);
    if (APR_SUCCESS != status) {
        return status;
    }

    if (!cur.absolute) {
        apr_file_printf(ds->err, "argument '%s': path not absolute.\n",
                apr_pescape_echo(ds->pool, pair->key, 1));
        return APR_EINVAL;
    }

    if (option) {
        option[0] = arg;
    }

    return APR_SUCCESS;
}

static apr_status_t device_parse_url_path_noscheme(device_set_t *ds, device_pair_t *pair,
        const char *arg, apr_array_header_t *options, const char **option)
{
    device_url_path_state_t cur = { 0 };
    apr_status_t status;

    if (!arg) {
        apr_file_printf(ds->err, "argument '%s': is empty.\n",
                apr_pescape_echo(ds->pool, pair->key, 1));
        return APR_INCOMPLETE;
    }

    if (pair->optional == DEVICE_IS_REQUIRED && !arg[0]) {
        apr_file_printf(ds->err, "'%s' is required\n", pair->key);
        return APR_EGENERAL;
    }
    else if (!arg[0]) {
        if (option) {
            option[0] = NULL;
        }
        return APR_SUCCESS;
    }

    status = device_parse_url_path_ex(ds, pair, arg, &cur, pair->up.max);
    if (APR_SUCCESS != status) {
        return status;
    }

    if (!cur.noscheme) {
        apr_file_printf(ds->err, "argument '%s': path contains a scheme\n",
                apr_pescape_echo(ds->pool, pair->key, 1));
        return APR_EINVAL;
    }

    if (option) {
        option[0] = arg;
    }

    return APR_SUCCESS;
}

static apr_status_t device_parse_url_path_rootless(device_set_t *ds, device_pair_t *pair,
        const char *arg, apr_array_header_t *options, const char **option)
{
    device_url_path_state_t cur = { 0 };
    apr_status_t status;

    if (!arg) {
        apr_file_printf(ds->err, "argument '%s': is empty.\n",
                apr_pescape_echo(ds->pool, pair->key, 1));
        return APR_INCOMPLETE;
    }

    if (pair->optional == DEVICE_IS_REQUIRED && !arg[0]) {
        apr_file_printf(ds->err, "'%s' is required\n", pair->key);
        return APR_EGENERAL;
    }
    else if (!arg[0]) {
        if (option) {
            option[0] = NULL;
        }
        return APR_SUCCESS;
    }

    status = device_parse_url_path_ex(ds, pair, arg, &cur, pair->up.max);
    if (APR_SUCCESS != status) {
        return status;
    }

    if (!cur.rootless) {
        apr_file_printf(ds->err, "argument '%s': path is not rootless\n",
                apr_pescape_echo(ds->pool, pair->key, 1));
        return APR_EINVAL;
    }

    if (option) {
        option[0] = arg;
    }

    return APR_SUCCESS;
}

static apr_status_t device_parse_url_path_empty(device_set_t *ds, device_pair_t *pair,
        const char *arg, apr_array_header_t *options, const char **option)
{
    device_url_path_state_t cur = { 0 };
    apr_status_t status;

    if (!arg) {
        apr_file_printf(ds->err, "argument '%s': is empty.\n",
                apr_pescape_echo(ds->pool, pair->key, 1));
        return APR_INCOMPLETE;
    }

    if (pair->optional == DEVICE_IS_REQUIRED && !arg[0]) {
        apr_file_printf(ds->err, "'%s' is required\n", pair->key);
        return APR_EGENERAL;
    }
    else if (!arg[0]) {
        if (option) {
            option[0] = NULL;
        }
        return APR_SUCCESS;
    }

    status = device_parse_url_path_ex(ds, pair, arg, &cur, pair->up.max);
    if (APR_SUCCESS != status) {
        return status;
    }

    if (!cur.empty) {
        apr_file_printf(ds->err, "argument '%s': path is not empty\n",
                apr_pescape_echo(ds->pool, pair->key, 1));
        return APR_EINVAL;
    }

    if (option) {
        option[0] = arg;
    }

    return APR_SUCCESS;
}

typedef enum device_uri_target_e {
    DEVICE_URI_TARGET = 0,
    DEVICE_URI_TARGET_ABSOLUTE,
    DEVICE_URI_TARGET_RELATIVE
} device_uri_target_e;

/*
 * Parse a URI.
 */
static apr_status_t device_parse_uri_ex(device_set_t *ds, device_pair_t *pair,
        const char *arg, device_uri_target_e target, apr_array_header_t *options, const char **option)
{
    apr_uri_t uri;
    apr_status_t status;

    if (!arg) {
        apr_file_printf(ds->err, "'%s': is empty.\n",
                apr_pescape_echo(ds->pool, pair->key, 1));
        return APR_INCOMPLETE;
    }

    if (pair->optional == DEVICE_IS_REQUIRED && !arg[0]) {
        apr_file_printf(ds->err, "'%s' is required\n", pair->key);
        return APR_EGENERAL;
    }
    else if (!arg[0]) {
        if (option) {
            option[0] = NULL;
        }
        return APR_SUCCESS;
    }

    status = apr_uri_parse(ds->pool, arg, &uri);

    if (APR_SUCCESS != status) {
        apr_file_printf(ds->err, "uri '%s' is not a valid uri.\n",
                apr_pescape_echo(ds->pool, arg, 1));
        return APR_EINVAL;
    }

    if (pair->uri.schemes) {
        if (!uri.scheme
                || !apr_hash_get(pair->uri.schemes, uri.scheme,
                        APR_HASH_KEY_STRING)) {
            apr_file_printf(ds->err, "scheme '%s' must be one of: %s\n",
                    apr_pescape_echo(ds->pool, uri.scheme, 1), device_hash_to_string(ds->pool, pair->uri.schemes));
            return APR_EINVAL;
        }
    }

    if (option) {
        option[0] = arg;
    }

    switch (target) {
    case DEVICE_URI_TARGET: {
        /* all uris accepted */
        if (uri.path) {
            device_url_path_state_t cur = { 0 };

            status = device_parse_url_path_ex(ds, pair, uri.path,
                    &cur, pair->uri.max);
            if (APR_SUCCESS != status) {
                return status;
            }
        }
        break;
    }
    case DEVICE_URI_TARGET_ABSOLUTE: {
        /* absolute means scheme is present and fragment is absent */
        if (!uri.scheme) {
            apr_file_printf(ds->err, "argument '%s': uri must have a scheme.\n",
                    apr_pescape_echo(ds->pool, pair->key, 1));
            return APR_EINVAL;
        }
        else if (uri.fragment) {
            apr_file_printf(ds->err, "argument '%s': uri must not have a fragment.\n",
                    apr_pescape_echo(ds->pool, pair->key, 1));
            return APR_EINVAL;
        }
        /* "//" authority path-abempty */
        else if (uri.hostinfo) {
            device_url_path_state_t cur = { 0 };

            status = device_parse_url_path_ex(ds, pair, uri.path,
                    &cur, pair->uri.max);
            if (APR_SUCCESS != status) {
                return status;
            }
        }
        /* path must be path-absolute, path-rootless, path-empty */
        else {
            device_url_path_state_t cur = { 0 };

            status = device_parse_url_path_ex(ds, pair, uri.path,
                    &cur, pair->uri.max);
            if (APR_SUCCESS != status) {
                return status;
            }

            if (!cur.absolute && !cur.rootless && !cur.empty) {
                apr_file_printf(ds->err,
                        "argument '%s': uri's path must be absolute, rootless, or empty.\n",
                        apr_pescape_echo(ds->pool, pair->key, 1));
                return APR_EINVAL;
            }
        }
        break;
    }
    case DEVICE_URI_TARGET_RELATIVE: {
        /* relative means scheme is absent */
        if (uri.scheme) {
            apr_file_printf(ds->err, "argument '%s': uri must not have a scheme.\n",
                    apr_pescape_echo(ds->pool, pair->key, 1));
            return APR_EINVAL;
        }
        else if (!uri.path) {
            apr_file_printf(ds->err, "argument '%s': uri must have a path.\n",
                    apr_pescape_echo(ds->pool, pair->key, 1));
            return APR_EINVAL;
        }
        /* "//" authority path-abempty */
        else if (uri.hostinfo) {
            device_url_path_state_t cur = { 0 };

            status = device_parse_url_path_ex(ds, pair, uri.path,
                    &cur, pair->uri.max);
            if (APR_SUCCESS != status) {
                return status;
            }
        }
        /* path must be path-absolute, path-noscheme, path-empty */
        else {
            device_url_path_state_t cur = { 0 };

            status = device_parse_url_path_ex(ds, pair, uri.path,
                    &cur, pair->uri.max);
            if (APR_SUCCESS != status) {
                return status;
            }

            if (!cur.absolute && !cur.noscheme && !cur.empty) {
                apr_file_printf(ds->err,
                        "argument '%s': uri's path must be absolute, relative with no scheme, or empty.\n",
                        apr_pescape_echo(ds->pool, pair->key, 1));
                return APR_EINVAL;
            }
        }

        break;
    }
    }

    return APR_SUCCESS;
}

static apr_status_t device_parse_uri(device_set_t *ds, device_pair_t *pair,
        const char *arg, apr_array_header_t *options, const char **option)
{
    return device_parse_uri_ex(ds, pair, arg, DEVICE_URI_TARGET, options, option);
}

static apr_status_t device_parse_uri_absolute(device_set_t *ds, device_pair_t *pair,
        const char *arg, apr_array_header_t *options, const char **option)
{
    return device_parse_uri_ex(ds, pair, arg, DEVICE_URI_TARGET_ABSOLUTE, options, option);
}

static apr_status_t device_parse_uri_relative(device_set_t *ds, device_pair_t *pair,
        const char *arg, apr_array_header_t *options, const char **option)
{
    return device_parse_uri_ex(ds, pair, arg, DEVICE_URI_TARGET_RELATIVE, options, option);
}

typedef struct device_address_state_t {
    unsigned int address:1;
    unsigned int mailbox:1;
    unsigned int group:1;
    unsigned int name_addr:1;
    unsigned int addr_spec:1;
    unsigned int display_name:1;
    unsigned int angle_addr:1;
    unsigned int local_part:1;
    unsigned int domain:1;
    unsigned int domain_literal:1;
    unsigned int group_list:1;
    unsigned int mailbox_list:1;
    unsigned int address_list:1;
    unsigned int phrase:1;
    unsigned int word:1;
    unsigned int atom:1;
    unsigned int quoted_string:1;
    unsigned int dot_atom:1;
    unsigned int dot_atom_text:1;
    unsigned int dns_atom:1;
    unsigned int seen_atext:1;
    unsigned int seen_left_cfws:1;
    unsigned int seen_right_cfws:1;
    unsigned int is_ws:1;
    unsigned int is_atext:1;
    unsigned int is_dnstext:1;
    unsigned int is_dot:1;
    unsigned int is_at:1;
    apr_size_t local_part_len;
    apr_size_t domain_label_len;
    apr_size_t domain_len;
} device_address_state_t;

static void want_dot_atom_text(device_address_state_t *cur)
{
    cur->dot_atom_text = 1;
}

static void want_dot_atom(device_address_state_t *cur)
{
    want_dot_atom_text(cur);
    cur->dot_atom = 1;
}

static void want_local_part(device_address_state_t *cur)
{
    want_dot_atom(cur);
    cur->local_part = 1;
    cur->local_part_len = 0;
}

static void want_dns_atom(device_address_state_t *cur)
{
    cur->dns_atom = 1;
}

static void want_domain(device_address_state_t *cur)
{
    want_dns_atom(cur);
    cur->domain = 1;
    cur->domain_len = 0;
    cur->domain_label_len = 0;
}

static void want_addr_spec(device_address_state_t *cur)
{
    want_local_part(cur);
    cur->addr_spec = 1;
}

static void want_mailbox(device_address_state_t *cur)
{
    want_addr_spec(cur);
    /* want_name_addr(cur); */
    cur->mailbox = 1;
}

static void want_address(device_address_state_t *cur)
{
    want_mailbox(cur);
    /* want_group(cur); */
    cur->address = 1;
}

static int is_filesafe(char c)
{
    switch (c) {
    case ':':
    case '/':
    case '\\':
        return 0;
    default:
        return 1;
    }
}

static int is_ws(char c)
{
    switch (c) {
    case '\t':
    case ' ':
        return 1;
    default:
        return 0;
    }
}

static int is_atext(char c)
{

    switch (c) {
    case '!':
    case '#':
    case '$':
    case '%':
    case '&':
    case '\'':
    case '*':
    case '+':
    case '-':
    case '/':
    case '=':
    case '?':
    case '^':
    case '_':
    case '`':
    case '{':
    case '|':
    case '}':
    case '~':
        return 1;
    }

    if (apr_isalnum(c)) {
        return 1;
    }

    return 0;
}

static int is_dnstext(char c)
{

    switch (c) {
    case '-':
        return 1;
    }

    if (apr_isalnum(c)) {
        return 1;
    }

    return 0;
}

static int is_at(char c)
{
    switch (c) {
    case '@':
        return 1;
    default:
        return 0;
    }
}

static int is_dot(char c)
{
    switch (c) {
    case '.':
        return 1;
    default:
        return 0;
    }
}

/*
 * Address matches the parts described by 3.4 of RFC5322.
 */
static apr_status_t device_parse_address_ex(device_set_t *ds, device_pair_t *pair,
        const char *arg, device_address_state_t *cur, apr_uint64_t max)
{
    apr_size_t len = 0;

    device_address_state_t prev = { 0 };

    cur->seen_atext = 0;
    cur->seen_left_cfws = 0;
    cur->seen_right_cfws = 0;

    if (!arg) {
        apr_file_printf(ds->err, "argument '%s': is missing.\n",
                apr_pescape_echo(ds->pool, pair->key, 1));
        return APR_INCOMPLETE;
    }

    while (1) {
        char c = arg[len++];

        /* not too long? */
        if (len >= max) {
            /* not ok */
            apr_file_printf(ds->err, "argument '%s': '%s' is too long (%" APR_SIZE_T_FMT " character limit).\n",
                    apr_pescape_echo(ds->pool, pair->key, 1),
                    apr_pescape_echo(ds->pool,
                            apr_pstrcat(ds->pool,
                                    apr_pstrndup(ds->pool, arg, 64), "...",
                                    NULL), 1), max);
            return APR_EINVAL;
        }

        /* local part too long? */
        if (cur->local_part_len > DEVICE_ADDRESS_LOCAL_PART_LIMIT) {
            /* not ok */
            apr_file_printf(ds->err, "argument '%s': address local part is too long (%" APR_SIZE_T_FMT " character limit).\n",
                    apr_pescape_echo(ds->pool, pair->key, 1),
                    (apr_size_t)DEVICE_ADDRESS_LOCAL_PART_LIMIT);
            return APR_EINVAL;
        }

        /* domain label too long? */
        if (cur->domain_label_len > DEVICE_ADDRESS_DOMAIN_LABEL_LIMIT) {
            /* not ok */
            apr_file_printf(ds->err, "argument '%s': address domain label is too long (%" APR_SIZE_T_FMT " character limit).\n",
                    apr_pescape_echo(ds->pool, pair->key, 1),
                    (apr_size_t)DEVICE_ADDRESS_DOMAIN_LABEL_LIMIT);
            return APR_EINVAL;
        }

        /* domain too long? */
        if (cur->domain_len > DEVICE_ADDRESS_DOMAIN_LIMIT) {
            /* not ok */
            apr_file_printf(ds->err, "argument '%s': address domain is too long (%" APR_SIZE_T_FMT " character limit).\n",
                    apr_pescape_echo(ds->pool, pair->key, 1),
                    (apr_size_t)DEVICE_ADDRESS_DOMAIN_LIMIT);
            return APR_EINVAL;
        }

        /* end of address */
        if (c == 0) {
            break;
        }

        prev = *cur;

        /* filesafe? */
        if (pair->a.filesafe && !is_filesafe(c)) {
            /* not ok */
            apr_file_printf(ds->err, "argument '%s': contains invalid character '%c'.\n",
                    apr_pescape_echo(ds->pool, pair->key, 1), c);
            return APR_EINVAL;
        }

        /* detect character type */
        cur->is_ws = is_ws(c);
        cur->is_atext = is_atext(c);
        cur->is_dnstext = is_dnstext(c);
        cur->is_dot = is_dot(c);
        cur->is_at = is_at(c);

        /* dot-atom-text   =   1*atext *("." 1*atext) */
        if (cur->dot_atom_text) {

            if (cur->is_atext) {
                /* ok */
            }
            else if (cur->is_dot) {
                if (!prev.is_atext) {
                    /* dot at start or dot repeated not ok */
                    return APR_EINVAL;
                }
            }
            else {
                if (prev.is_atext) {
                    /* ok */
                    cur->dot_atom_text = 0;
                }
                else if (prev.is_dot) {
                    /* dot at end not ok */
                    return APR_EINVAL;
                }
                else {
                    /* empty dot_atom_text not ok */
                    return APR_EINVAL;
                }
            }

        }

        /* dot-atom        =   [CFWS] dot-atom-text [CFWS] */
        if (cur->dot_atom) {

//            if (cur->is_ws) {
//                /* we don't support whitespace for now */
//                return APR_ENOTIMPL;
//            }

            if (!cur->dot_atom_text) {
                /* our dot-atom is finished */
                cur->dot_atom = 0;
            }
        }

        /* local-part      =   dot-atom / quoted-string */
        if (cur->local_part) {
            if (!cur->dot_atom && !cur->quoted_string) {
                cur->local_part = 0;
            }
            else {
                cur->local_part_len++;
            }
        }

        /* dns-atom   =   1*dnstext *("." 1*dnstext) */
        if (cur->dns_atom) {

            if (cur->is_dnstext) {
                /* ok */
                if (cur->is_dot) {
                    cur->domain_label_len = 0;
                }
                else {
                    cur->domain_label_len++;
                }
            }
            else if (cur->is_dot) {
                if (!prev.is_dnstext) {
                    /* dot at start or dot repeated not ok */
                    return APR_EINVAL;
                }
            }
            else {
                if (prev.is_dnstext) {
                    /* ok */
                    cur->dns_atom = 0;
                }
                else if (prev.is_dot) {
                    /* dot at end not ok */
                    return APR_EINVAL;
                }
                else {
                    /* empty dns_atom_text not ok */
                    return APR_EINVAL;
                }
            }

        }

        /* rfc5322#section-3.2.3 defines the liberal dot-atom */
        /* domain          =   dot-atom / domain-literal */
        /* rfc5321#section-2.3.5 defines the SMTP domain */
        /* domain = dns-atom / domain-literal */
        if (cur->domain) {
            if (!cur->dns_atom && !cur->domain_literal) {
                cur->domain = 0;
            }
            else {
                cur->domain_len++;
            }
        }

        /* addr-spec       =   local-part "@" domain */
        if (cur->addr_spec) {

            if (!cur->local_part && !cur->is_at && !cur->domain) {
                /* we are no longer an addr_spec */
                cur->addr_spec = 0;
            }
            else if (!cur->domain && cur->is_at) {
                /* transition from local-part to domain */
                want_domain(cur);
                cur->domain_literal = 0;
            }
        }

        /* mailbox         =   name-addr / addr-spec */
        if (cur->mailbox) {
            if (!cur->name_addr && !cur->addr_spec) {
                cur->mailbox = 0;
            }
        }

        /* address         =   mailbox / group */
        if (cur->address) {
            if (!cur->mailbox && !cur->group) {
                cur->address = 0;
                apr_file_printf(ds->err, "argument '%s': is not an address at character %" APR_SIZE_T_FMT ".\n",
                        apr_pescape_echo(ds->pool, pair->key, 1), len);
                return APR_EINVAL;
            }
        }

    }

    /* did the address finish early? */

    /* dot-atom-text   =   1*atext *("." 1*atext) */
    if (cur->dot_atom_text) {
        if (cur->is_dot) {
            /* no domain */
            apr_file_printf(ds->err, "argument '%s': address ends with a dot.\n",
                    apr_pescape_echo(ds->pool, pair->key, 1));
            return APR_EINVAL;
        }

    }

    /* dns-atom   =   1*dnstext *("." 1*dnstext) */
    if (cur->dns_atom) {
        if (cur->is_dot) {
            /* no domain */
            apr_file_printf(ds->err, "argument '%s': address domain ends with a dot.\n",
                    apr_pescape_echo(ds->pool, pair->key, 1));
            return APR_EINVAL;
        }

    }

    /* addr-spec       =   local-part "@" domain */
    if (cur->addr_spec) {

        if (cur->local_part) {
            /* no at symbol */
            apr_file_printf(ds->err, "argument '%s': address is missing an '@'.\n",
                    apr_pescape_echo(ds->pool, pair->key, 1));
            return APR_EINVAL;
        }
        else if (cur->is_at) {
            /* no domain */
            apr_file_printf(ds->err, "argument '%s': address is missing a domain.\n",
                    apr_pescape_echo(ds->pool, pair->key, 1));
            return APR_EINVAL;
        }
    }

    return APR_SUCCESS;
}

static apr_status_t device_parse_address_localpart(device_set_t *ds, device_pair_t *pair,
        const char *arg, apr_array_header_t *options, const char **option)
{
    device_address_state_t cur = { 0 };
    apr_status_t status;

    if (!arg) {
        apr_file_printf(ds->err, "argument '%s': is empty.\n",
                apr_pescape_echo(ds->pool, pair->key, 1));
        return APR_INCOMPLETE;
    }

    if (pair->optional == DEVICE_IS_REQUIRED && !arg[0]) {
        apr_file_printf(ds->err, "'%s' is required\n", pair->key);
        return APR_EGENERAL;
    }
    else if (!arg[0]) {
        if (option) {
            option[0] = NULL;
        }
        return APR_SUCCESS;
    }

    want_local_part(&cur);

    status = device_parse_address_ex(ds, pair, arg, &cur, pair->a.max);
    if (APR_SUCCESS != status) {
        return status;
    }

    if (!cur.local_part) {
        apr_file_printf(ds->err, "argument '%s': local-part is not valid\n",
                apr_pescape_echo(ds->pool, pair->key, 1));
        return APR_EINVAL;
    }

    if (option) {
        option[0] = arg;
    }

    return APR_SUCCESS;
}

static apr_status_t device_parse_address(device_set_t *ds, device_pair_t *pair,
        const char *arg, apr_array_header_t *options, const char **option)
{
    device_address_state_t cur = { 0 };
    apr_status_t status;

    if (!arg) {
        apr_file_printf(ds->err, "argument '%s': is empty.\n",
                apr_pescape_echo(ds->pool, pair->key, 1));
        return APR_INCOMPLETE;
    }

    if (pair->optional == DEVICE_IS_REQUIRED && !arg[0]) {
        apr_file_printf(ds->err, "'%s' is required\n", pair->key);
        return APR_EGENERAL;
    }
    else if (!arg[0]) {
        if (option) {
            option[0] = NULL;
        }
        return APR_SUCCESS;
    }

    want_address(&cur);

    status = device_parse_address_ex(ds, pair, arg, &cur, pair->a.max);
    if (APR_SUCCESS != status) {
        return status;
    }

    if (!cur.address) {
        apr_file_printf(ds->err, "argument '%s': address is not valid\n",
                apr_pescape_echo(ds->pool, pair->key, 1));
        return APR_EINVAL;
    }

    if (option) {
        option[0] = arg;
    }

    return APR_SUCCESS;
}

static apr_status_t device_parse_address_mailbox(device_set_t *ds, device_pair_t *pair,
        const char *arg, apr_array_header_t *options, const char **option)
{
    device_address_state_t cur = { 0 };
    apr_status_t status;

    if (!arg) {
        apr_file_printf(ds->err, "argument '%s': is empty.\n",
                apr_pescape_echo(ds->pool, pair->key, 1));
        return APR_INCOMPLETE;
    }

    if (pair->optional == DEVICE_IS_REQUIRED && !arg[0]) {
        apr_file_printf(ds->err, "'%s' is required\n", pair->key);
        return APR_EGENERAL;
    }
    else if (!arg[0]) {
        if (option) {
            option[0] = NULL;
        }
        return APR_SUCCESS;
    }

    want_mailbox(&cur);

    status = device_parse_address_ex(ds, pair, arg, &cur, pair->a.max);
    if (APR_SUCCESS != status) {
        return status;
    }

    if (!cur.mailbox) {
        apr_file_printf(ds->err, "argument '%s': mailbox is not valid\n",
                apr_pescape_echo(ds->pool, pair->key, 1));
        return APR_EINVAL;
    }

    if (option) {
        option[0] = arg;
    }

    return APR_SUCCESS;
}

static apr_status_t device_parse_address_addrspec(device_set_t *ds, device_pair_t *pair,
        const char *arg, apr_array_header_t *options, const char **option)
{
    device_address_state_t cur = { 0 };
    apr_status_t status;

    if (!arg) {
        apr_file_printf(ds->err, "argument '%s': is empty.\n",
                apr_pescape_echo(ds->pool, pair->key, 1));
        return APR_INCOMPLETE;
    }

    if (pair->optional == DEVICE_IS_REQUIRED && !arg[0]) {
        apr_file_printf(ds->err, "'%s' is required\n", pair->key);
        return APR_EGENERAL;
    }
    else if (!arg[0]) {
        if (option) {
            option[0] = NULL;
        }
        return APR_SUCCESS;
    }

    want_addr_spec(&cur);

    status = device_parse_address_ex(ds, pair, arg, &cur, pair->a.max);
    if (APR_SUCCESS != status) {
        return status;
    }

    if (!cur.addr_spec) {
        apr_file_printf(ds->err, "argument '%s': address is not valid\n",
                apr_pescape_echo(ds->pool, pair->key, 1));
        return APR_EINVAL;
    }

    if (option) {
        option[0] = arg;
    }

    return APR_SUCCESS;
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
            const char *name = NULL;
            apr_finfo_t finfo;
            const char *keyname;
            const char *relname;
            char *keypath;
            char *relpath;
            apr_off_t len;

            apr_pool_create(&pool, ds->pool);

            switch (pair->type) {

            case DEVICE_PAIR_INDEX:
            case DEVICE_PAIR_PORT:
            case DEVICE_PAIR_UNPRIVILEGED_PORT:
            case DEVICE_PAIR_HOSTNAME:
            case DEVICE_PAIR_FQDN:
            case DEVICE_PAIR_SELECT:
            case DEVICE_PAIR_BYTES:
            case DEVICE_PAIR_SQL_IDENTIFIER:
            case DEVICE_PAIR_SQL_DELIMITED_IDENTIFIER:
            case DEVICE_PAIR_USER:
            case DEVICE_PAIR_DISTINGUISHED_NAME:
            case DEVICE_PAIR_POLAR:
            case DEVICE_PAIR_SWITCH:
            case DEVICE_PAIR_INTEGER:
            case DEVICE_PAIR_TEXT:
            case DEVICE_PAIR_URL_PATH:
            case DEVICE_PAIR_URL_PATH_ABEMPTY:
            case DEVICE_PAIR_URL_PATH_ABSOLUTE:
            case DEVICE_PAIR_URL_PATH_NOSCHEME:
            case DEVICE_PAIR_URL_PATH_ROOTLESS:
            case DEVICE_PAIR_URL_PATH_EMPTY:
            case DEVICE_PAIR_ADDRESS:
            case DEVICE_PAIR_ADDRESS_LOCALPART:
            case DEVICE_PAIR_ADDRESS_MAILBOX:
            case DEVICE_PAIR_ADDRESS_ADDRSPEC:

                keyname = apr_pstrcat(pool, pair->key, pair->suffix, NULL);
                if (APR_SUCCESS
                        != (status = apr_filepath_merge(&keypath, dirent.name,
                                keyname, APR_FILEPATH_NOTABSOLUTE, pool))) {
                    apr_file_printf(ds->err, "cannot merge option set key '%s': %pm\n", pair->key,
                            &status);
                }

                /* open/seek/read the key */
                else if (APR_SUCCESS
                        != (status = device_file_read(ds, pool, pair->key, keypath,
                                &name, &len))) {
                    /* error already handled */
                }

                break;

            case DEVICE_PAIR_SYMLINK:

                keyname = apr_pstrcat(pool, pair->key, pair->suffix, NULL);
                if (APR_SUCCESS
                        != (status = apr_filepath_merge(&keypath, dirent.name,
                                keyname, APR_FILEPATH_NOTABSOLUTE, pool))) {
                    apr_file_printf(ds->err, "cannot merge option set key '%s': %pm\n", pair->key,
                            &status);
                }

                /* stat the key */
                else if (APR_SUCCESS
                        != (status = apr_stat(&finfo, keypath, APR_FINFO_LINK | APR_FINFO_TYPE | APR_FINFO_NAME,
                                pool))) {
                    apr_file_printf(ds->err, "cannot stat option set '%s': %pm\n", pair->key,
                            &status);
                }

                else {

                    int size = strlen(finfo.name);

                    if (size >= pair->s.symlink_suffix_len) {
                        name = apr_pstrndup(ds->pool, finfo.name, size - pair->s.symlink_suffix_len);
                    }
                    else {
                        apr_file_printf(ds->err, "option set '%s' does not have suffix: %s\n", pair->key,
                                pair->s.symlink_suffix);
                        status = APR_EGENERAL;
                    }

                }

                break;

            case DEVICE_PAIR_RELATION:

                keyname = apr_pstrcat(pool, pair->key, pair->suffix, NULL);
                relname = apr_pstrcat(pool, pair->r.relation_name,
                        pair->r.relation_suffix, NULL);
                if (APR_SUCCESS
                        != (status = apr_filepath_merge(&keypath, dirent.name,
                                keyname, APR_FILEPATH_NOTABSOLUTE, pool))) {
                    apr_file_printf(ds->err, "cannot merge option set key '%s' (base): %pm\n", pair->key,
                            &status);
                }

                /* find relation */
                else if (APR_SUCCESS
                        != (status = apr_filepath_merge(&relpath, keypath,
                                relname, APR_FILEPATH_NOTABSOLUTE, pool))) {
                    apr_file_printf(ds->err, "cannot merge option set key '%s' (name): %pm\n", pair->key,
                            &status);
                }
                else if (pair->r.relation_prefix && APR_SUCCESS
                        != (status = apr_filepath_merge(&relpath, relpath,
                                pair->r.relation_prefix, APR_FILEPATH_NOTABSOLUTE, pool))) {
                    apr_file_printf(ds->err, "cannot merge option set key '%s' (name): %pm\n", pair->key,
                            &status);
                }

                /* open/seek/read the key */
                else if (APR_SUCCESS
                        != (status = device_file_read(ds, pool, pair->key, relpath,
                                &name, &len))) {
                    /* error already handled */
                }

                break;

            case DEVICE_PAIR_HEX:
            case DEVICE_PAIR_URI:
            case DEVICE_PAIR_URI_ABSOLUTE:
            case DEVICE_PAIR_URI_RELATIVE:
                /* support me */
                apr_pool_destroy(pool);
                continue;
            }

            if (status != APR_SUCCESS) {
                apr_pool_destroy(pool);
                continue;
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
    const char *keypath = NULL, *keyval = NULL;
    apr_status_t status = APR_SUCCESS;
    int i;

    /* save the present working directory */
    status = apr_filepath_get(&pwd, APR_FILEPATH_NATIVE, ds->pool);

    if (APR_SUCCESS != status) {
        apr_file_printf(ds->err, "cannot access cwd: %pm\n", &status);
        return status;
    }

    if (ds->mode == DEVICE_ADD) {

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
                apr_file_printf(ds->err, "cannot create add mark '%s': %pm\n", ds->key,
                    &status);
                return status;
            }
            else if (APR_SUCCESS != (status = apr_file_close(out))) {
                apr_file_printf(ds->err, "cannot close add mark '%s': %pm\n", ds->key, &status);
                return status;
            }
            else if (APR_SUCCESS
                    != (status = apr_file_perms_set(DEVICE_ADD_MARKER,
                            APR_FPROT_OS_DEFAULT & ~DEVICE_FILE_UMASK))) {
                apr_file_printf(ds->err, "cannot set permissions to add mark '%s': %pm\n",
                        ds->key, &status);
                return status;
            }

        }
        else {
            apr_file_printf(ds->err, "option is unset\n");
            return APR_EGENERAL;
        }

    }
    else if (ds->mode == DEVICE_REINDEX) {

        /* no preparation needed */

    }
    else {

        if (ds->key) {

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
            apr_file_printf(ds->err, "cannot create set mark '%s': %pm\n", ds->key,
                    &status);
            return status;
        } else if (APR_SUCCESS != (status = apr_file_close(out))) {
            apr_file_printf(ds->err, "cannot close set mark '%s': %pm\n", ds->key,
                    &status);
            return status;
        } else if (APR_SUCCESS != (status = apr_file_perms_set(DEVICE_SET_MARKER,
                APR_FPROT_OS_DEFAULT & ~DEVICE_FILE_UMASK))) {
            apr_file_printf(ds->err, "cannot set permissions to set mark '%s': %pm\n",
                    ds->key, &status);
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
            if (symlink(file->link, file->template) && APR_SUCCESS != (status = errno)) {
                apr_file_printf(ds->err, "cannot link '%s': %pm\n", file->key, &status);
                break;
            }
        }

        if (file->index == DEVICE_IS_INDEXED) {
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

        /* remove the added/updated markers here */
        if (ds->mode == DEVICE_ADD && APR_SUCCESS !=
                (status = apr_file_remove(DEVICE_ADD_MARKER, ds->pool))
                && !APR_STATUS_IS_ENOENT(status)) {
            apr_file_printf(ds->err, "cannot remove add mark: %pm\n", &status);
        }
        if (ds->mode == DEVICE_SET && APR_SUCCESS !=
                (status = apr_file_remove(DEVICE_SET_MARKER, ds->pool))
                && !APR_STATUS_IS_ENOENT(status)) {
            apr_file_printf(ds->err, "cannot remove set mark: %pm\n", &status);
        }

        if (ds->key) {

            /* revert to present working directory */
            status = apr_filepath_set(pwd, ds->pool);
            if (APR_SUCCESS != status) {
                apr_file_printf(ds->err, "cannot revert '%s': %pm\n", ds->key, &status);
                return status;
            }

            if (ds->mode == DEVICE_ADD) {
                if (APR_SUCCESS != (status = apr_dir_remove(keypath, ds->pool))) {
                    apr_file_printf(ds->err, "cannot remove '%s': %pm\n", ds->key, &status);
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

            if (file->template && APR_SUCCESS != (status = apr_file_rename(file->template, file->dest, ds->pool))
                    && !APR_STATUS_IS_ENOENT(status)) {
                apr_file_printf(ds->err, "cannot move '%s': %pm\n", file->key, &status);
            }

            if (file->backup && APR_SUCCESS != (status = apr_file_remove(file->backup, ds->pool))
                    && !APR_STATUS_IS_ENOENT(status)) {
                apr_file_printf(ds->err, "cannot remove '%s': %pm\n", file->key, &status);
            }

            if (file->index == DEVICE_IS_INDEXED) {

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
            apr_file_remove(keyval, ds->pool);
            if (symlink(keypath, keyval)) {
                /* silently ignore any errors */
            }
        }

        return APR_SUCCESS;
    }

}

static apr_status_t device_command(device_set_t *ds, apr_array_header_t *files)
{

    apr_procattr_t *procattr;
    apr_proc_t *proc;

    apr_status_t status = APR_SUCCESS;
    int i, j;
    int exitcode = 0;
    apr_exit_why_e exitwhy = 0;

    if (ds->key) {

        char *var = apr_pstrcat(ds->pool, "DEVICE_", ds->key, NULL);

        for (j = 7; var && var[j]; j++) {
            var[j] = apr_toupper(var[j]);
        }

        apr_env_set(var, ds->keyval, ds->pool);

        /* change current working directory */
        status = apr_filepath_set(ds->keypath, ds->pool);

        if (APR_SUCCESS != status) {
            apr_file_printf(ds->err, "cannot access '%s': %pm\n", ds->key, &status);
            return status;
        }


    }


    /* set up environment */
    for (i = 0; i < files->nelts; i++)
    {
        device_file_t *file = &APR_ARRAY_IDX(files, i, device_file_t);

        char *var = apr_pstrcat(ds->pool, "DEVICE_", file->key, NULL);

        for (j = 7; var && var[j]; j++) {
            var[j] = apr_toupper(var[j]);
        }

        if (!file->val) {

            /* no value, leave unset */

        }
        else if (file->type == APR_REG) {

            apr_env_set(var, file->val, ds->pool);

        }
        else if (file->type == APR_LNK) {

            apr_env_set(var, file->link, ds->pool);

        }

    }

    if ((status = apr_procattr_create(&procattr, ds->pool)) != APR_SUCCESS) {
        apr_file_printf(ds->err, "cannot create procattr: %pm\n", &status);
        return status;
    }

    if ((status = apr_procattr_cmdtype_set(procattr, APR_PROGRAM_ENV)) != APR_SUCCESS) {
        apr_file_printf(ds->err, "cannot set command type in procattr: %pm\n", &status);
        return status;
    }

    proc = apr_pcalloc(ds->pool, sizeof(apr_proc_t));
    if ((status = apr_proc_create(proc, ds->argv[0], (const char* const*) ds->argv,
            NULL, procattr, ds->pool)) != APR_SUCCESS) {
        apr_file_printf(ds->err, "cannot run command: %pm\n", &status);
        return status;
    }

    if ((status = apr_proc_wait(proc, &exitcode, &exitwhy, APR_WAIT)) != APR_CHILD_DONE) {
        apr_file_printf(ds->err, "cannot wait for command: %pm\n", &status);
        return status;
    }

    if (exitcode != 0 || exitwhy != APR_PROC_EXIT) {
        if (exitwhy != APR_PROC_EXIT) {
            apr_file_printf(ds->err, "command exited %s with code %d\n",
                    APR_PROC_CHECK_EXIT(exitwhy) ? "normally" :
                    APR_PROC_CHECK_SIGNALED(exitwhy) ? "on signal" :
                    APR_PROC_CHECK_CORE_DUMP(exitwhy) ? "and dumped core" : "",
                    exitcode);
        }
        return APR_EGENERAL;
    }

    return APR_SUCCESS;
}

static apr_status_t device_complete(device_set_t *ds, const char **args)
{
    const char *key = NULL, *value = NULL;

    apr_status_t status;
    int start = 0, count;

    if (!args[0]) {
        /* no args is not ok */
        apr_file_printf(ds->err, "complete needs one or more arguments.\n");
        return APR_EINVAL;
    }

    if (ds->key && (ds->mode == DEVICE_SET || ds->mode == DEVICE_RENAME || ds->mode == DEVICE_EXEC)) {

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
            status = device_get(ds, args[0], options, &ds->keyval, &ds->keypath, NULL);

            if (APR_SUCCESS != status) {
                return status;
            }
        }

        start = 2;
    }

    /* find the last key/value pair, or just the key if odd */
    count = start;
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

    if (ds->mode == DEVICE_REMOVE || ds->mode == DEVICE_MARK || ds->mode == DEVICE_SHOW) {
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
                status = device_parse_index(ds, pair, value, NULL, NULL);
                break;
            case DEVICE_PAIR_PORT:
                status = device_parse_port(ds, pair, value, NULL);
                break;
            case DEVICE_PAIR_UNPRIVILEGED_PORT:
                status = device_parse_unprivileged_port(ds, pair, value, NULL);
                break;
            case DEVICE_PAIR_HOSTNAME:
                status = device_parse_hostname(ds, pair, value, NULL);
                break;
            case DEVICE_PAIR_FQDN:
                status = device_parse_fqdn(ds, pair, value, NULL);
                break;
            case DEVICE_PAIR_SELECT:
                status = device_parse_select(ds, pair, value, options, NULL);
                break;
            case DEVICE_PAIR_BYTES:
                status = device_parse_bytes(ds, pair, value, options, NULL);
                break;
            case DEVICE_PAIR_SYMLINK:
                status = device_parse_symlink(ds, pair, value, options, NULL, NULL);
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
            case DEVICE_PAIR_RELATION:
                status = device_parse_relation(ds, pair, value, options, NULL, NULL);
                break;
            case DEVICE_PAIR_POLAR:
                status = device_parse_polar(ds, pair, value, options, NULL);
                break;
            case DEVICE_PAIR_SWITCH:
                status = device_parse_switch(ds, pair, value, options, NULL);
                break;
            case DEVICE_PAIR_INTEGER:
                status = device_parse_integer(ds, pair, value, options, NULL);
                break;
            case DEVICE_PAIR_HEX:
                status = device_parse_hex(ds, pair, value, options, NULL);
                break;
            case DEVICE_PAIR_TEXT:
                status = device_parse_text(ds, pair, value, options, NULL);
                break;
            case DEVICE_PAIR_URL_PATH:
                status = device_parse_url_path(ds, pair, value, options, NULL);
                break;
            case DEVICE_PAIR_URL_PATH_ABEMPTY:
                status = device_parse_url_path_abempty(ds, pair, value, options, NULL);
                break;
            case DEVICE_PAIR_URL_PATH_ABSOLUTE:
                status = device_parse_url_path_absolute(ds, pair, value, options, NULL);
                break;
            case DEVICE_PAIR_URL_PATH_NOSCHEME:
                status = device_parse_url_path_noscheme(ds, pair, value, options, NULL);
                break;
            case DEVICE_PAIR_URL_PATH_ROOTLESS:
                status = device_parse_url_path_rootless(ds, pair, value, options, NULL);
                break;
            case DEVICE_PAIR_URL_PATH_EMPTY:
                status = device_parse_url_path_empty(ds, pair, value, options, NULL);
                break;
            case DEVICE_PAIR_URI:
                status = device_parse_uri(ds, pair, value, options, NULL);
                break;
            case DEVICE_PAIR_URI_ABSOLUTE:
                status = device_parse_uri_absolute(ds, pair, value, options, NULL);
                break;
            case DEVICE_PAIR_URI_RELATIVE:
                status = device_parse_uri_relative(ds, pair, value, options, NULL);
                break;
            case DEVICE_PAIR_ADDRESS:
                status = device_parse_address(ds, pair, value, options, NULL);
                break;
            case DEVICE_PAIR_ADDRESS_MAILBOX:
                status = device_parse_address_mailbox(ds, pair, value, options, NULL);
                break;
            case DEVICE_PAIR_ADDRESS_ADDRSPEC:
                status = device_parse_address_addrspec(ds, pair, value, options, NULL);
                break;
            case DEVICE_PAIR_ADDRESS_LOCALPART:
                status = device_parse_address_localpart(ds, pair, value, options, NULL);
                break;
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

            int found = 0;

            apr_hash_this(hi, NULL, NULL, &v);
            pair = v;

            /* skip primary key when setting but not renaming */
            if (ds->key && ds->mode == DEVICE_SET && !strcmp(ds->key, pair->key)) {
                continue;
            }

            /* skip keys already seen in arguments */
            count = start;
            while(args[count]) {
                if (!args[count + 1]) {
                    break;
                }
                if (!strcmp(pair->key, args[count])) {
                    found = 1;
                    break;
                }
                count += 2;
            }
            if (found) {
                continue;
            }

            /* suggest remaining key */
            if (!key || !key[0] || !strncmp(key, pair->key, strlen(key))) {
                apr_file_printf(ds->out, "%c%s=\n",
                        pair->optional == DEVICE_IS_OPTIONAL ? '-' : '*',
                        device_pescape_shell(ds->pool, pair->key));
            }

        }

        status = APR_INCOMPLETE;

    }

    apr_file_flush(ds->out);
    apr_file_flush(ds->err);

    return status;
}

/*
 * Default index value is one higher than the highest
 * current value.
 */
static apr_status_t device_default_index(device_set_t *ds, device_pair_t *pair,
        apr_array_header_t *files)
{
    apr_dir_t *thedir;
    apr_finfo_t dirent;

    apr_status_t status;

    apr_int64_t max = 0;

    /* scan the directories to find a match */
    if ((status = apr_dir_open(&thedir, ".", ds->pool)) != APR_SUCCESS) {
        /* could not open directory, fail */
        apr_file_printf(ds->err, "could not open current directory: %pm\n", &status);
        return status;
    }

    do {

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
            char *val = NULL;
            apr_file_t *in;
            const char *indexname;
            char *indexpath;
            apr_off_t end = 0, start = 0;

            apr_pool_create(&pool, ds->pool);

            indexname = apr_pstrcat(pool, pair->key, pair->suffix, NULL);
            if (APR_SUCCESS
                    != (status = apr_filepath_merge(&indexpath, dirent.name,
                            indexname, APR_FILEPATH_NOTABSOLUTE, pool))) {
                apr_file_printf(ds->err, "cannot merge option set key '%s': %pm\n", pair->key,
                        &status);
            }

            /* open the index */
            else if (APR_SUCCESS
                    != (status = apr_file_open(&in, indexpath, APR_FOPEN_READ,
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
                apr_file_printf(ds->err, "cannot seek start of option set '%s': %pm\n", pair->key,
                        &status);
            }

            else {
                int size = end + 1;
                val = apr_palloc(pool, size);
                val[end] = 0;

                status = apr_file_gets(val, size, in);

                if (APR_EOF == status) {
                    status = APR_SUCCESS;
                }
                if (APR_SUCCESS == status) {
                    /* short circuit, all good */
                    val = trim(val);
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
            else {

                char *end;

                /* parse index, is it the largest so far? */

                apr_int64_t index = apr_strtoi64(val, &end, 10);
                if (end[0] || errno == ERANGE) {
                    apr_file_printf(ds->err, "argument '%s': '%s' is not a valid index, ignoring.\n",
                            apr_pescape_echo(ds->pool, pair->key, 1),
                            apr_pescape_echo(ds->pool, val, 1));
                    /* ignore and loop round */
                }
                else if (index == APR_INT64_MAX) {
                    apr_file_printf(ds->err, "argument '%s': existing index '%s' is too big.\n",
                            apr_pescape_echo(ds->pool, pair->key, 1),
                            apr_pescape_echo(ds->pool, val, 1));
                    return APR_EGENERAL;
                }

                if (index >= max) {
                    max = index + 1;
                }
            }

            apr_pool_destroy(pool);

            break;
        }
        default:
            break;
        }

    } while (1);

    apr_dir_close(thedir);

    if (APR_SUCCESS == status) {
        /* short circuit, all good */
    }
    else if (APR_STATUS_IS_ENOENT(status)) {
        status = APR_SUCCESS;
    }
    else {
        apr_file_printf(ds->err, "cannot read indexes: %pm\n",
                &status);
        return status;
    }

    device_file_t *file;

    file = apr_array_push(files);
    file->type = APR_REG;

    file->dest = apr_pstrcat(ds->pool, pair->key, pair->suffix, NULL);
    file->template = apr_pstrcat(ds->pool, file->dest, ".XXXXXX", NULL);
    file->key = pair->key;
    file->val = apr_psprintf(ds->pool, "%" APR_INT64_T_FMT, max);
    file->index = pair->index;

    return APR_SUCCESS;
}

/*
 * Default polar answer is the option given (yes/no).
 */
static apr_status_t device_default_polar(device_set_t *ds, device_pair_t *pair,
        apr_array_header_t *files)
{
    device_file_t *file;

    file = apr_array_push(files);
    file->type = APR_REG;

    file->dest = apr_pstrcat(ds->pool, pair->key, pair->suffix, NULL);
    file->template = apr_pstrcat(ds->pool, file->dest, ".XXXXXX", NULL);
    file->key = pair->key;
    file->val = pair->p.polar_default ? "" : NULL;
    file->index = pair->index;

    return APR_SUCCESS;
}

/*
 * Default switch is the option given (on/off).
 */
static apr_status_t device_default_switch(device_set_t *ds, device_pair_t *pair,
        apr_array_header_t *files)
{
    device_file_t *file;

    file = apr_array_push(files);
    file->type = APR_REG;

    file->dest = apr_pstrcat(ds->pool, pair->key, pair->suffix, NULL);
    file->template = apr_pstrcat(ds->pool, file->dest, ".XXXXXX", NULL);
    file->key = pair->key;
    file->val = pair->sw.switch_default ? "" : NULL;
    file->index = pair->index;

    return APR_SUCCESS;
}

static apr_status_t device_default(device_set_t *ds, device_pair_t *pair, apr_array_header_t *files)
{
    apr_status_t status;

    switch (pair->type) {
    case DEVICE_PAIR_INDEX:
        status = device_default_index(ds, pair, files);
        break;
    case DEVICE_PAIR_POLAR:
        status = device_default_polar(ds, pair, files);
        break;
    case DEVICE_PAIR_SWITCH:
        status = device_default_switch(ds, pair, files);
        break;
    default:
        status = APR_SUCCESS;
    }

    return status;
}

static apr_status_t device_parse(device_set_t *ds, const char *key, const char *val, apr_array_header_t *files)
{
    device_file_t *file;
    device_pair_t *pair;

    apr_status_t status = APR_SUCCESS;

    /* look up the parameter */
    pair = apr_hash_get(ds->pairs, key, APR_HASH_KEY_STRING);

    if (pair) {

        apr_array_header_t *options = apr_array_make(ds->pool, (10), sizeof(char *));

        apr_filetype_e type = APR_REG;

        const char *link = NULL;

        switch (pair->type) {
        case DEVICE_PAIR_INDEX:
            status = device_parse_index(ds, pair, val, &val, files);
            break;
        case DEVICE_PAIR_PORT:
            status = device_parse_port(ds, pair, val, &val);
            break;
        case DEVICE_PAIR_UNPRIVILEGED_PORT:
            status = device_parse_unprivileged_port(ds, pair, val, &val);
            break;
        case DEVICE_PAIR_HOSTNAME:
            status = device_parse_hostname(ds, pair, val, &val);
            break;
        case DEVICE_PAIR_FQDN:
            status = device_parse_fqdn(ds, pair, val, &val);
            break;
        case DEVICE_PAIR_SELECT:
            status = device_parse_select(ds, pair, val, options, &val);
            break;
        case DEVICE_PAIR_BYTES:
            status = device_parse_bytes(ds, pair, val, options, &val);
            break;
        case DEVICE_PAIR_SYMLINK:
            status = device_parse_symlink(ds, pair, val, options, &val, &link);
            type = APR_LNK;
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
        case DEVICE_PAIR_RELATION:
            status = device_parse_relation(ds, pair, val, options, &val, &link);
            type = APR_LNK;
            break;
        case DEVICE_PAIR_POLAR:
            status = device_parse_polar(ds, pair, val, options, &val);
            break;
        case DEVICE_PAIR_SWITCH:
            status = device_parse_switch(ds, pair, val, options, &val);
            break;
        case DEVICE_PAIR_INTEGER:
            status = device_parse_integer(ds, pair, val, options, &val);
            break;
        case DEVICE_PAIR_HEX:
            status = device_parse_hex(ds, pair, val, options, &val);
            break;
        case DEVICE_PAIR_TEXT:
            status = device_parse_text(ds, pair, val, options, &val);
            break;
        case DEVICE_PAIR_URL_PATH:
            status = device_parse_url_path(ds, pair, val, options, &val);
            break;
        case DEVICE_PAIR_URL_PATH_ABEMPTY:
            status = device_parse_url_path_abempty(ds, pair, val, options, &val);
            break;
        case DEVICE_PAIR_URL_PATH_ABSOLUTE:
            status = device_parse_url_path_absolute(ds, pair, val, options, &val);
            break;
        case DEVICE_PAIR_URL_PATH_NOSCHEME:
            status = device_parse_url_path_noscheme(ds, pair, val, options, &val);
            break;
        case DEVICE_PAIR_URL_PATH_ROOTLESS:
            status = device_parse_url_path_rootless(ds, pair, val, options, &val);
            break;
        case DEVICE_PAIR_URL_PATH_EMPTY:
            status = device_parse_url_path_empty(ds, pair, val, options, &val);
            break;
        case DEVICE_PAIR_URI:
            status = device_parse_uri(ds, pair, val, options, &val);
            break;
        case DEVICE_PAIR_URI_ABSOLUTE:
            status = device_parse_uri_absolute(ds, pair, val, options, &val);
            break;
        case DEVICE_PAIR_URI_RELATIVE:
            status = device_parse_uri_relative(ds, pair, val, options, &val);
            break;
        case DEVICE_PAIR_ADDRESS:
            status = device_parse_address(ds, pair, val, options, &val);
            break;
        case DEVICE_PAIR_ADDRESS_MAILBOX:
            status = device_parse_address_mailbox(ds, pair, val, options, &val);
            break;
        case DEVICE_PAIR_ADDRESS_ADDRSPEC:
            status = device_parse_address_addrspec(ds, pair, val, options, &val);
            break;
        case DEVICE_PAIR_ADDRESS_LOCALPART:
            status = device_parse_address_localpart(ds, pair, val, options, &val);
            break;
        }

        file = apr_array_push(files);
        file->type = type;

        file->dest = apr_pstrcat(ds->pool, pair->key, pair->suffix, NULL);
        file->template = apr_pstrcat(ds->pool, file->dest, ".XXXXXX", NULL);
        file->key = key;
        file->val = val;
        file->link = link;
        file->index = pair->index;

        if (APR_SUCCESS != status) {
            return status;
        }

        pair->set = DEVICE_IS_SET;

        if (pair->unique == DEVICE_IS_UNIQUE) {

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

        if (pair->optional == DEVICE_IS_REQUIRED && !file->val) {
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

        apr_hash_index_t *hi;
        void *v;
        device_pair_t *pair;

        /* check for required options that remain unset */

        for (hi = apr_hash_first(ds->pool, ds->pairs); hi; hi = apr_hash_next(hi)) {

            apr_hash_this(hi, NULL, NULL, &v);
            pair = v;

            if (pair->set != DEVICE_IS_SET) {

                status = device_default(ds, pair, files);

                if (APR_SUCCESS != status) {
                    return status;
                }

                if (pair->optional == DEVICE_IS_REQUIRED
                        && pair->set == DEVICE_IS_UNSET) {
                    apr_file_printf(ds->err, "'%s' is required.\n",
                            apr_pescape_echo(ds->pool, pair->key, 1));
                    return APR_EINVAL;
                }

            }

        }

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

        if (ds->mode != DEVICE_RENAME && ds->key && !strcmp(key, ds->key)) {
            apr_file_printf(ds->err, "'%s' cannot be modified.\n",
                    apr_pescape_echo(ds->pool, key, 1));
            return APR_EINVAL;
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

static apr_status_t device_rename(device_set_t *ds, const char **args)
{

    return device_set(ds, args);
}

static apr_status_t device_value(device_set_t *ds, device_pair_t *pair,
        const char *keypath, apr_array_header_t *values, const char **keyval,
        apr_int64_t *order, int *max)
{
    char *path;
    device_value_t *value;
    const char *val = NULL;
    apr_off_t len = 0;

    apr_status_t status;

    switch (pair->type) {
    case DEVICE_PAIR_PORT:
    case DEVICE_PAIR_UNPRIVILEGED_PORT:
    case DEVICE_PAIR_HOSTNAME:
    case DEVICE_PAIR_FQDN:
    case DEVICE_PAIR_SELECT:
    case DEVICE_PAIR_BYTES:
    case DEVICE_PAIR_SQL_IDENTIFIER:
    case DEVICE_PAIR_SQL_DELIMITED_IDENTIFIER:
    case DEVICE_PAIR_USER:
    case DEVICE_PAIR_DISTINGUISHED_NAME:
    case DEVICE_PAIR_INTEGER:
    case DEVICE_PAIR_TEXT:
    case DEVICE_PAIR_HEX:
    case DEVICE_PAIR_URL_PATH:
    case DEVICE_PAIR_URL_PATH_ABEMPTY:
    case DEVICE_PAIR_URL_PATH_ABSOLUTE:
    case DEVICE_PAIR_URL_PATH_NOSCHEME:
    case DEVICE_PAIR_URL_PATH_ROOTLESS:
    case DEVICE_PAIR_URL_PATH_EMPTY:
    case DEVICE_PAIR_URI:
    case DEVICE_PAIR_URI_ABSOLUTE:
    case DEVICE_PAIR_URI_RELATIVE:
    case DEVICE_PAIR_ADDRESS:
    case DEVICE_PAIR_ADDRESS_LOCALPART:
    case DEVICE_PAIR_ADDRESS_MAILBOX:
    case DEVICE_PAIR_ADDRESS_ADDRSPEC: {

        const char *keyname;
        apr_finfo_t finfo;

        keyname = path = apr_pstrcat(ds->pool, pair->key, pair->suffix,
        NULL);
        if (keypath
                && APR_SUCCESS
                        != (status = apr_filepath_merge(&path, keypath, keyname,
                                APR_FILEPATH_NOTABSOLUTE, ds->pool))) {
            apr_file_printf(ds->err, "cannot merge option set key '%s': %pm\n",
                    pair->key, &status);
            break;
        }

        /* stat the file */
        status = apr_stat(&finfo, path,
        APR_FINFO_TYPE, ds->pool);
        if (APR_ENOENT == status) {
            /* missing - ignore the file */

            /* FIXME: the none/default option goes here */

            break;
        } else if (APR_SUCCESS != status) {
            apr_file_printf(ds->err, "cannot stat option set '%s': %pm\n",
                    pair->key, &status);
            break;
        }

        /* open/seek/read the file */
        if (APR_SUCCESS
                != (status = device_file_read(ds, ds->pool, pair->key, path,
                        &val, &len))) {
            /* error already handled */
            break;
        }

        value = apr_array_push(values);
        value->pair = pair;
        value->value = val;
        value->len = len;
        value->set = 1;

        max[0] = max[0] > value->len ? max[0] : value->len;

        break;
    }
    case DEVICE_PAIR_POLAR:
    case DEVICE_PAIR_SWITCH: {

        const char *keyname;
        apr_finfo_t finfo;

        keyname = path = apr_pstrcat(ds->pool, pair->key, pair->suffix,
        NULL);
        if (keypath
                && APR_SUCCESS
                        != (status = apr_filepath_merge(&path, keypath, keyname,
                                APR_FILEPATH_NOTABSOLUTE, ds->pool))) {
            apr_file_printf(ds->err, "cannot merge option set key '%s': %pm\n",
                    pair->key, &status);
            break;
        }

        /* stat the file */
        status = apr_stat(&finfo, path,
        APR_FINFO_TYPE, ds->pool);
        if (APR_ENOENT == status) {

            value = apr_array_push(values);
            value->pair = pair;

            switch (pair->type) {
            case DEVICE_PAIR_POLAR:

                value->value = "no";
                value->len = strlen("no");

                break;
            case DEVICE_PAIR_SWITCH:

                value->value = "off";
                value->len = strlen("off");

                break;
            default:
                break;
            }

            max[0] = max[0] > value->len ? max[0] : value->len;

        } else if (APR_SUCCESS == (status)) {

            value = apr_array_push(values);
            value->pair = pair;

            switch (pair->type) {
            case DEVICE_PAIR_POLAR:

                value->value = "yes";
                value->len = strlen("yes");
                value->set = 1;

                break;
            case DEVICE_PAIR_SWITCH:

                value->value = "on";
                value->len = strlen("on");
                value->set = 1;

                break;
            default:
                break;
            }

            max[0] = max[0] > value->len ? max[0] : value->len;

        } else {
            apr_file_printf(ds->err, "cannot stat option set '%s': %pm\n",
                    pair->key, &status);
            break;
        }

        break;
    }
    case DEVICE_PAIR_INDEX: {

        const char *keyname;
        apr_finfo_t finfo;
        char *end;

        if (!order) {
            status = APR_ENOENT;
            break;
        }

        keyname = path = apr_pstrcat(ds->pool, pair->key, pair->suffix,
        NULL);
        if (keypath
                && APR_SUCCESS
                        != (status = apr_filepath_merge(&path, keypath, keyname,
                                APR_FILEPATH_NOTABSOLUTE, ds->pool))) {
            apr_file_printf(ds->err, "cannot merge option set key '%s': %pm\n",
                    pair->key, &status);
            break;
        }

        /* stat the file */
        status = apr_stat(&finfo, path,
        APR_FINFO_TYPE, ds->pool);
        if (APR_ENOENT == status) {
            /* missing - ignore the file */
            break;
        } else if (APR_SUCCESS != status) {
            apr_file_printf(ds->err, "cannot stat option set '%s': %pm\n",
                    pair->key, &status);
            break;
        }

        /* open/seek/read the file */
        if (APR_SUCCESS
                != (status = device_file_read(ds, ds->pool, pair->key, path,
                        &val, &len))) {
            /* error already handled */
            break;
        }

        order[0] = apr_strtoi64(val, &end, 10);
        status = apr_get_os_error();
        if (end[0] || status == APR_ERANGE) {
            apr_file_printf(ds->err,
                    "argument '%s': '%s' is not a valid index, ignoring.\n",
                    apr_pescape_echo(ds->pool, pair->key, 1),
                    apr_pescape_echo(ds->pool, val, 1));
            /* ignore and loop round */
            break;
        }

        value = apr_array_push(values);
        value->pair = pair;
        value->value = val;
        value->len = len;
        value->set = 1;

        max[0] = max[0] > value->len ? max[0] : value->len;

        break;
    }
    case DEVICE_PAIR_SYMLINK: {

        const char *keyname;
        apr_finfo_t finfo;
        char target[PATH_MAX];
        apr_ssize_t size;

        keyname = path = apr_pstrcat(ds->pool, pair->key, pair->suffix,
        NULL);
        if (keypath
                && APR_SUCCESS
                        != (status = apr_filepath_merge(&path, keypath, keyname,
                                APR_FILEPATH_NOTABSOLUTE, ds->pool))) {
            apr_file_printf(ds->err, "cannot merge option set key '%s': %pm\n",
                    pair->key, &status);
            break;
        }

        /* stat the link */
        status = apr_stat(&finfo, path,
        APR_FINFO_LINK | APR_FINFO_TYPE, ds->pool);
        if (APR_ENOENT == status) {
            /* missing - ignore the file */
            status = APR_SUCCESS;

            value = apr_array_push(values);
            value->pair = pair;

            switch (pair->optional) {
            case DEVICE_IS_OPTIONAL:

                if (pair->unset) {
                    value->len = strlen(pair->unset);
                    value->value = pair->unset;
                }
                else {
                    value->len = strlen(DEVICE_SYMLINK_NONE);
                    value->value = DEVICE_SYMLINK_NONE;
                }

                break;
            case DEVICE_IS_REQUIRED:

                value->len = strlen(DEVICE_SYMLINK_ERROR);
                value->value = DEVICE_SYMLINK_ERROR;

                break;
            }

            max[0] = max[0] > value->len ? max[0] : value->len;

            break;
        } else if (finfo.filetype != APR_LNK) {
            apr_file_printf(ds->err,
                    "option set '%s': link expected, ignoring\n", pair->key);
            break;
        } else if (APR_SUCCESS != status) {
            apr_file_printf(ds->err, "cannot stat option set '%s': %pm\n",
                    pair->key, &status);
            break;
        }

        /* stat the key */
        if ((size = readlink(path, target, sizeof(target))) < 0) {
            status = apr_get_os_error();
            apr_file_printf(ds->err, "cannot readlink option set '%s': %pm\n",
                    pair->key, &status);
        }

        else {

            const char *val;

            int i;
            int found = 0;

            /* match the base path */
            for (i = 0; i < pair->s.bases->nelts; i++) {

                char *base = APR_ARRAY_IDX(pair->s.bases, i, char *);

                int baselen = strlen(base);

                /* ignore trailing '/' if it exists */
                if (baselen && base[baselen - 1] == '/') {
                    baselen--;
                }

                /* do we have a prefix match? */
                if (baselen <= size && !strncmp(base, target, baselen)) {

                    val = target + baselen;
                    size = size - baselen;

                    /* do we have exact match or a '/' at the end? */
                    if (!size || val[0] == '/') {
                        found = 1;
                        break;
                    }

                }

            }

            /* oops, no base path matches */
            if (!found) {
                apr_file_printf(ds->err,
                        "option set '%s' does not exist beneath bases.\n", pair->key);
                status = APR_EGENERAL;
            }

            if (!pair->s.symlink_recursive && size && val[0] == '/') {

                /* skip past '/' */
                val++;
                size--;

            }

            if (size >= pair->s.symlink_suffix_len) {

                apr_ssize_t len = size - pair->s.symlink_suffix_len;
                val = apr_pstrndup(ds->pool, val, len);

                value = apr_array_push(values);
                value->pair = pair;
                value->value = val;
                value->len = strlen(val);
                value->set = 1;

                max[0] = max[0] > value->len ? max[0] : value->len;

            } else {
                apr_file_printf(ds->err,
                        "option set '%s' does not have suffix: %s\n", pair->key,
                        pair->s.symlink_suffix);
                status = APR_EGENERAL;
            }

        }

        break;

    }
    case DEVICE_PAIR_RELATION: {

        const char *keyname;
        const char *relname;
        char *relpath;
        apr_finfo_t finfo;

        keyname = path = apr_pstrcat(ds->pool, pair->key, pair->suffix,
        NULL);
        if (keypath
                && APR_SUCCESS
                        != (status = apr_filepath_merge(&path, keypath, keyname,
                                APR_FILEPATH_NOTABSOLUTE, ds->pool))) {
            apr_file_printf(ds->err, "cannot merge option set key '%s': %pm\n",
                    pair->key, &status);
            break;
        }

        /* stat the file */
        status = apr_stat(&finfo, path,
        APR_FINFO_LINK | APR_FINFO_TYPE, ds->pool);
        if (APR_ENOENT == status) {
            /* missing - optional or error */

            value = apr_array_push(values);
            value->pair = pair;

            switch (pair->optional) {
            case DEVICE_IS_OPTIONAL:

                if (pair->unset) {
                    value->len = strlen(pair->unset);
                    value->value = pair->unset;
                }
                else {
                    value->len = strlen(DEVICE_RELATION_NONE);
                    value->value = DEVICE_RELATION_NONE;
                }

                break;
            case DEVICE_IS_REQUIRED:

                value->len = strlen(DEVICE_RELATION_ERROR);
                value->value = DEVICE_RELATION_ERROR;

                break;
            }

            max[0] = max[0] > value->len ? max[0] : value->len;

            break;
        } else if (APR_SUCCESS != status) {
            apr_file_printf(ds->err, "cannot stat option set '%s': %pm\n",
                    pair->key, &status);
            break;
        }

        relname = apr_pstrcat(ds->pool, pair->r.relation_name,
                pair->r.relation_suffix, NULL);

        /* find relation */
        if (APR_SUCCESS
                != (status = apr_filepath_merge(&relpath, path, relname,
                        APR_FILEPATH_NOTABSOLUTE, ds->pool))) {
            apr_file_printf(ds->err, "cannot merge option set key '%s': %pm\n",
                    pair->key, &status);
            break;
        }

        /* open/seek/read the file */
        else if (APR_SUCCESS
                != (status = device_file_read(ds, ds->pool, pair->key, relpath,
                        &val, &len))) {
            /* error already handled */
            break;
        }

        value = apr_array_push(values);
        value->pair = pair;
        value->value = val;
        value->len = len;
        value->set = 1;

        max[0] = max[0] > value->len ? max[0] : value->len;

        break;

    }
    }

    if (keyval && pair->key && ds->key && !strcmp(pair->key, ds->key)) {
        keyval[0] = val;
    }

    return status;
}

static apr_status_t device_list(device_set_t *ds, const char **args)
{
    apr_dir_t *thedir;
    apr_finfo_t dirent;
    device_table_t *table;
    device_row_t *row;
    device_value_t *value;

    char *upper;

    apr_array_header_t *rows = apr_array_make(ds->pool,
            16, sizeof(device_row_t));

    apr_status_t status = APR_SUCCESS;

    int i, j, k;

    if (!ds->show_table) {
        apr_file_printf(ds->err, "Name to show was not specified.\n");
        return APR_EINVAL;
    }

    /* scan the directories to create our list */
    if ((status = apr_dir_open(&thedir, ".", ds->pool)) != APR_SUCCESS) {
        /* could not open directory, fail */
        apr_file_printf(ds->err, "could not open current directory: %pm\n", &status);
        return status;
    }

    do {

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

            row = apr_array_push(rows);
            row->indexes = apr_array_make(ds->pool, 16, sizeof(device_value_t));
            row->flags = apr_array_make(ds->pool, 16, sizeof(device_value_t));
            row->values = apr_array_make(ds->pool, 16, sizeof(device_value_t));

            for (i = 0; i < ds->show_index->nelts; i++) {
                table = &APR_ARRAY_IDX(ds->show_index, i, device_table_t);

                status = device_value(ds, table->pair, dirent.name, row->indexes, &row->keyval, &row->order, &table->max);

                if (APR_SUCCESS != status) {
                    device_value_t *value;
                    value = apr_array_push(row->flags);
                    value->pair = table->pair;
                    value->value = "";
                    value->len = 0;
                }

            }

            for (i = 0; i < ds->show_flags->nelts; i++) {
                table = &APR_ARRAY_IDX(ds->show_flags, i, device_table_t);

                status = device_value(ds, table->pair, dirent.name, row->flags, &row->keyval, &row->order, &table->max);

                if (APR_SUCCESS != status) {
                    device_value_t *value;
                    value = apr_array_push(row->flags);
                    value->pair = table->pair;
                    value->value = "";
                    value->len = 0;
                }

            }

            for (i = 0; i < ds->show_table->nelts; i++) {
                table = &APR_ARRAY_IDX(ds->show_table, i, device_table_t);

                status = device_value(ds, table->pair, dirent.name, row->values, &row->keyval, &row->order, &table->max);

                if (APR_SUCCESS != status) {
                    device_value_t *value;
                    value = apr_array_push(row->values);
                    value->pair = table->pair;
                    value->value = "";
                    value->len = 0;
                }

            }

            break;
        }
        default:
            break;
        }

    } while (1);

    apr_dir_close(thedir);

    /* flags summary row */
    if (ds->show_flags->nelts) {
        apr_file_puts("Flags: ", ds->out);
        for (j = 0; j < ds->show_flags->nelts; j++) {

            table = &APR_ARRAY_IDX(ds->show_flags, j, device_table_t);

            if (j) {
                apr_file_puts(",", ds->out);
            }

            if (table->pair->flag) {
                apr_file_printf(ds->out, "%s (%s)", table->pair->key, table->pair->flag);
            } else {
                apr_file_printf(ds->out, "%s", table->pair->key);
            }

        }
        apr_file_puts("\n", ds->out);
    }

    /* index header row */
    for (j = 0; j < ds->show_index->nelts; j++) {

        table = &APR_ARRAY_IDX(ds->show_index, j, device_table_t);

        apr_file_printf(ds->out, "%*s ", table->max, "#");

    }

    /* flags header row */
    if (ds->show_flags->nelts) {
        for (j = 0; j < ds->show_flags->nelts; j++) {

            table = &APR_ARRAY_IDX(ds->show_flags, j, device_table_t);

            if (table->pair->flag) {
                apr_file_printf(ds->out, "%*s", (int)strlen(table->pair->flag), "");
            } else {
                apr_file_puts(" ", ds->out);
            }

        }
        apr_file_puts(" ", ds->out);
    }

    /* values header row */
    for (j = 0; j < ds->show_table->nelts; j++) {

        table = &APR_ARRAY_IDX(ds->show_table, j, device_table_t);

        upper = apr_pstrdup(ds->pool, table->pair->key);
        for (k = 0; upper[k]; k++) {
            upper[k] = apr_toupper(upper[k]);
        }

        apr_file_printf(ds->out, "%*s  ", table->max, upper);

    }
    apr_file_puts("\n", ds->out);

    /* sort by order, then by key */
    qsort(rows->elts, rows->nelts, rows->elt_size, rows_asc);

    /* rows */
    for (i = 0; i < rows->nelts; i++) {
        row = &APR_ARRAY_IDX(rows, i, device_row_t);

        for (j = 0; j < row->indexes->nelts && j < ds->show_index->nelts; j++) {
            table = &APR_ARRAY_IDX(ds->show_index, j, device_table_t);
            value = &APR_ARRAY_IDX(row->indexes, j, device_value_t);

            apr_file_printf(ds->out, "%*s ", table->max, value->value);

        }

        for (j = 0; j < row->flags->nelts && j < ds->show_flags->nelts; j++) {
            table = &APR_ARRAY_IDX(ds->show_flags, j, device_table_t);
            value = &APR_ARRAY_IDX(row->flags, j, device_value_t);

            if (value->set) {
                if (table->pair->flag) {
                    apr_file_printf(ds->out, "%*s", (int)strlen(table->pair->flag),
                            table->pair->flag);
                } else {
                    apr_file_puts(".", ds->out);
                }
            }
            else {
                if (table->pair->flag) {
                    apr_file_printf(ds->out, "%*s", (int)strlen(table->pair->flag),
                            "");
                } else {
                    apr_file_puts(" ", ds->out);
                }
            }

        }
        if (ds->show_flags->nelts) {
            apr_file_puts(" ", ds->out);
        }

        for (j = 0; j < row->values->nelts && j < ds->show_table->nelts; j++) {
            table = &APR_ARRAY_IDX(ds->show_table, j, device_table_t);
            value = &APR_ARRAY_IDX(row->values, j, device_value_t);

            apr_file_printf(ds->out, "%*s  ", table->max, value->value);

        }
        apr_file_puts("\n", ds->out);

    }

    return APR_SUCCESS;
}

static apr_status_t device_show(device_set_t *ds, const char **args)
{
    apr_hash_index_t *hi;
    void *v;
    device_pair_t *pair;
    apr_off_t len;

    apr_array_header_t *values = apr_array_make(ds->pool,
            16, sizeof(device_value_t));

    apr_status_t status = APR_SUCCESS;

    int i, max;

    if (ds->key) {

        if (!args[0] || !args[1]) {

            /* no args gives full list */
            return device_list(ds, args);

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

    for (hi = apr_hash_first(ds->pool, ds->pairs); hi; hi = apr_hash_next(hi)) {

        apr_hash_this(hi, NULL, NULL, &v);
        pair = v;

        device_value(ds, pair, ds->keypath, values, NULL, NULL, &max);

    }


    max = 0;

    qsort(values->elts, values->nelts, values->elt_size, values_asc);

    for (i = 0; i < values->nelts; i++) {
        device_value_t *value = &APR_ARRAY_IDX(values, i, device_value_t);

        len = strlen(value->pair->key);
        max = max > len ? max : len;
    }

    for (i = 0; i < values->nelts; i++) {
        device_value_t *value = &APR_ARRAY_IDX(values, i, device_value_t);

        apr_file_printf(ds->out, "%*s: %s\n", max, value->pair->key, value->value);
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

static apr_status_t device_reindex(device_set_t *ds, const char **args)
{
    apr_hash_index_t *hi;
    void *v;
    device_pair_t *pair;

    apr_array_header_t *files = apr_array_make(ds->pool,
            16, sizeof(device_file_t));

    apr_status_t status = APR_SUCCESS;

    for (hi = apr_hash_first(ds->pool, ds->pairs); hi; hi = apr_hash_next(hi)) {

        apr_hash_this(hi, NULL, NULL, &v);
        pair = v;

        if (pair->type == DEVICE_PAIR_INDEX) {

            apr_dir_t *thedir;
            apr_finfo_t dirent;

            apr_array_header_t *tfiles = apr_array_make(ds->pool, 16, sizeof(device_file_t));
            apr_array_header_t *sfiles = apr_array_make(ds->pool, 16, sizeof(device_file_t));

            int i, nelts;

            /* scan the directories to find a match */
            if ((status = apr_dir_open(&thedir, ".", ds->pool)) != APR_SUCCESS) {
                /* could not open directory, fail */
                apr_file_printf(ds->err, "could not open current directory: %pm\n", &status);
                return status;
            }

            do {

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

                    apr_pool_create(&pool, ds->pool);

                    char *val = NULL;
                    apr_file_t *in;
                    const char *indexname;
                    char *indexpath;
                    apr_off_t end = 0, start = 0;


                    indexname = apr_pstrcat(pool, pair->key, pair->suffix, NULL);
                    if (APR_SUCCESS
                            != (status = apr_filepath_merge(&indexpath, dirent.name,
                                    indexname, APR_FILEPATH_NOTABSOLUTE, pool))) {
                        apr_file_printf(ds->err, "cannot merge option set key '%s': %pm\n", pair->key,
                                &status);
                    }

                    /* open the index */
                    else if (APR_SUCCESS
                            != (status = apr_file_open(&in, indexpath, APR_FOPEN_READ,
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
                        apr_file_printf(ds->err, "cannot seek start of option set '%s': %pm\n", pair->key,
                                &status);
                    }

                    else {
                        int size = end + 1;
                        val = apr_palloc(pool, size);
                        val[end] = 0;

                        status = apr_file_gets(val, size, in);

                        if (APR_EOF == status) {
                            status = APR_SUCCESS;
                        }
                        if (APR_SUCCESS == status) {
                            /* short circuit, all good */
                            val = trim(val);
                        }
                        else {
                            apr_file_printf(ds->err, "cannot read option set '%s': %pm\n", pair->key,
                                    &status);
                        }
                    }

                    if (status != APR_SUCCESS) {
                        apr_pool_destroy(pool);
                        continue;
                    }
                    else {

                        char *end;

                        device_file_t *file;

                        apr_int64_t order = apr_strtoi64(val, &end, 10);
                        if (end[0] || errno == ERANGE) {
                            apr_file_printf(ds->err, "argument '%s': '%s' is not a valid index, ignoring.\n",
                                    apr_pescape_echo(ds->pool, pair->key, 1),
                                    apr_pescape_echo(ds->pool, val, 1));
                            /* ignore and loop round */
                        }
                        else {

                            /* add index */
                            file = apr_array_push(tfiles);
                            file->type = APR_REG;
                            file->order = order;

                            file->dest = indexpath;
                            file->template = apr_pstrcat(ds->pool, file->dest, ".XXXXXX", NULL);
                            file->key = pair->key;
                            file->val = apr_pstrdup(ds->pool, dirent.name);
                            file->index = pair->index;

                        }

                    }

                    apr_pool_destroy(pool);

                    break;
                }
                case APR_LNK: {

                    if (pair->index == DEVICE_IS_INDEXED) {

                        device_file_t *old;

                        /* remove old index */
                        old = apr_array_push(sfiles);
                        old->type = APR_LNK;

                        old->dest = apr_pstrdup(ds->pool, dirent.name);
                        old->key = pair->key;
                        old->val = NULL; /* delete the index */
                        old->link = NULL;
                        old->index = pair->index;

                    }

                    break;
                }
                default:
                    break;
                }

            } while (1);

            apr_dir_close(thedir);

            if (APR_SUCCESS == status) {
                /* short circuit, all good */
            }
            else if (APR_STATUS_IS_ENOENT(status)) {
                status = APR_SUCCESS;
            }
            else {
                apr_file_printf(ds->err, "cannot read indexes: %pm\n",
                        &status);
                return status;
            }

            apr_array_cat(files, sfiles);

            /* sort tfiles small to large so reindex doesn't stomp on files */
            qsort(tfiles->elts, tfiles->nelts, tfiles->elt_size, files_asc);

            for (i = 0, nelts = tfiles->nelts; i < nelts; i++) {

                const char *slink;

                device_file_t *file = &APR_ARRAY_IDX(tfiles, i, device_file_t);

                slink = apr_psprintf(ds->pool, "%d", i);

                if (file->index == DEVICE_IS_INDEXED) {

                    device_file_t *link;

                    /* add symlink */
                    link = apr_array_push(tfiles);
                    link->type = APR_LNK;
                    link->order = i;

                    link->dest = slink;
                    link->key = pair->key;
                    link->link = file->link;
                    link->index = DEVICE_IS_NORMAL;
                }

                file->link = slink;

            }

            apr_array_cat(files, tfiles);

        }

    }

    status = device_files(ds, files);

    return status;
}

static apr_status_t device_exec(device_set_t *ds, const char **args)
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
        status = device_command(ds, files);
    }

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
    device_optional_e optional = DEVICE_IS_OPTIONAL;

    apr_uint64_t bytes_min = 0;
    apr_uint64_t bytes_max = 0;

    apr_uint64_t sqlid_min = DEVICE_SQL_IDENTIFIER_DEFAULT_MIN;
    apr_uint64_t sqlid_max = DEVICE_SQL_IDENTIFIER_DEFAULT_MAX;

    device_polar_e polar_default = DEVICE_POLAR_DEFAULT_VAL;
    device_switch_e switch_default = DEVICE_SWITCH_DEFAULT_VAL;

    apr_int64_t integer_min;
    apr_int64_t integer_max;

    apr_uint64_t hex_min;
    apr_uint64_t hex_max;

    apr_int64_t hex_width;

    device_case_e hex_case = DEVICE_HEX_CASE_VAL;

    apr_uint64_t text_min = DEVICE_TEXT_MIN_DEFAULT;
    apr_uint64_t text_max = DEVICE_TEXT_MAX_DEFAULT;
    const char *text_format = DEVICE_TEXT_FORMAT_DEFAULT;

    apr_uint64_t url_path_max = DEVICE_URL_PATH_MAX_DEFAULT;
    apr_uint64_t uri_max = DEVICE_URI_MAX_DEFAULT;

    apr_uint64_t address_max = DEVICE_ADDRESS_MAX_DEFAULT;
    int address_noquotes = DEVICE_ADDRESS_NOQUOTES_DEFAULT;
    int address_filesafe = DEVICE_ADDRESS_FILESAFE_DEFAULT;

    const char *flag = NULL;
    const char *show_index = NULL;
    const char *show_flags = NULL;
    const char *show_table = NULL;

    const char *unset = NULL;

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

    device_parse_int64(&ds, "min", &integer_min);
    device_parse_int64(&ds, "max", &integer_max);

    device_parse_hex64(&ds, "min", &hex_min);
    device_parse_hex64(&ds, "max", &hex_max);

    setlocale(LC_CTYPE,"");

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
        case 'n': {
            ds.mode = DEVICE_RENAME;
            ds.key = optarg;
            break;
        }
        case DEVICE_OPTIONAL: {
            optional = DEVICE_IS_OPTIONAL;
            break;
        }
        case DEVICE_REQUIRED: {
            optional = DEVICE_IS_REQUIRED;
            break;
        }
        case 'r': {
            ds.mode = DEVICE_REINDEX;
            ds.key = optarg;
            break;
        }
        case 's': {
            ds.mode = DEVICE_SET;
            ds.key = optarg;
            break;
        }
        case 'g': {
            ds.mode = DEVICE_SHOW;
            if (optarg[0] != '-') {
                ds.key = optarg;
            }
            break;
        }
        case 'l': {
            ds.mode = DEVICE_LIST;
            break;
        }
        case 'e': {
            ds.mode = DEVICE_EXEC;
            if (optarg[0] != '-') {
                ds.key = optarg;
            }
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
        case DEVICE_DEFAULT: {
            unset = optarg;
            break;
        }
        case DEVICE_INDEX: {

            device_pair_t *pair = apr_pcalloc(ds.pool, sizeof(device_pair_t));

            pair->type = DEVICE_PAIR_INDEX;
            pair->key = optarg;
            pair->suffix = DEVICE_INDEX_SUFFIX;
            pair->optional = optional;
            pair->set = DEVICE_IS_DEFAULT;
            pair->flag = flag;
            pair->unset = unset;

            apr_hash_set(ds.pairs, optarg, APR_HASH_KEY_STRING, pair);

            flag = NULL;
            unset = NULL;

            break;
        }
        case DEVICE_PORT: {

            device_pair_t *pair = apr_pcalloc(ds.pool, sizeof(device_pair_t));

            pair->type = DEVICE_PAIR_PORT;
            pair->key = optarg;
            pair->suffix = DEVICE_TXT_SUFFIX;
            pair->optional = optional;
            pair->flag = flag;
            pair->unset = unset;

            apr_hash_set(ds.pairs, optarg, APR_HASH_KEY_STRING, pair);

            flag = NULL;
            unset = NULL;

            break;
        }
        case DEVICE_UNPRIVILEGED_PORT: {

            device_pair_t *pair = apr_pcalloc(ds.pool, sizeof(device_pair_t));

            pair->type = DEVICE_PAIR_UNPRIVILEGED_PORT;
            pair->key = optarg;
            pair->suffix = DEVICE_TXT_SUFFIX;
            pair->optional = optional;
            pair->flag = flag;
            pair->unset = unset;

            apr_hash_set(ds.pairs, optarg, APR_HASH_KEY_STRING, pair);

            flag = NULL;
            unset = NULL;

            break;
        }
        case DEVICE_HOSTNAME: {

            device_pair_t *pair = apr_pcalloc(ds.pool, sizeof(device_pair_t));

            pair->type = DEVICE_PAIR_HOSTNAME;
            pair->key = optarg;
            pair->suffix = DEVICE_TXT_SUFFIX;
            pair->optional = optional;
            pair->flag = flag;
            pair->unset = unset;

            apr_hash_set(ds.pairs, optarg, APR_HASH_KEY_STRING, pair);

            flag = NULL;
            unset = NULL;

            break;
        }
        case DEVICE_FQDN: {

            device_pair_t *pair = apr_pcalloc(ds.pool, sizeof(device_pair_t));

            pair->type = DEVICE_PAIR_FQDN;
            pair->key = optarg;
            pair->suffix = DEVICE_TXT_SUFFIX;
            pair->optional = optional;
            pair->flag = flag;
            pair->unset = unset;

            apr_hash_set(ds.pairs, optarg, APR_HASH_KEY_STRING, pair);

            flag = NULL;
            unset = NULL;

            break;
        }
        case DEVICE_SELECT: {

            device_pair_t *pair = apr_pcalloc(ds.pool, sizeof(device_pair_t));

            pair->type = DEVICE_PAIR_SELECT;
            pair->key = optarg;
            pair->suffix = DEVICE_TXT_SUFFIX;
            pair->optional = optional;
            pair->flag = flag;
            pair->sl.bases = ds.select_bases;
            pair->unset = unset;

            apr_hash_set(ds.pairs, optarg, APR_HASH_KEY_STRING, pair);

            ds.select_bases = NULL;
            flag = NULL;
            unset = NULL;

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
            pair->flag = flag;
            pair->unset = unset;
            pair->b.min = bytes_min;
            pair->b.max = bytes_max;

            apr_hash_set(ds.pairs, optarg, APR_HASH_KEY_STRING, pair);

            flag = NULL;
            unset = NULL;

            break;
        }
        case DEVICE_BYTES_MIN: {

            status = device_parse_uint64(&ds, optarg, &bytes_min);
            if (APR_SUCCESS != status) {
                exit(2);
            }

            break;
        }
        case DEVICE_BYTES_MAX: {

            status = device_parse_uint64(&ds, optarg, &bytes_max);
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
            pair->flag = flag;
            pair->unset = unset;
            pair->s.bases = ds.symlink_bases;
            pair->s.symlink_suffix = ds.symlink_suffix;
            pair->s.symlink_suffix_len = ds.symlink_suffix_len;
            pair->s.symlink_context_type = ds.symlink_context_type;
            pair->s.symlink_recursive = ds.symlink_recursive;

            apr_hash_set(ds.pairs, optarg, APR_HASH_KEY_STRING, pair);

            ds.symlink_bases = NULL;
            ds.symlink_suffix = NULL;
            ds.symlink_suffix_len = 0;
            ds.symlink_context_type = NULL;
            ds.symlink_recursive = 0;
            flag = NULL;
            unset = NULL;

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
        case DEVICE_SYMLINK_CONTEXT_TYPE: {
            ds.symlink_context_type = optarg;
            break;
        }
        case DEVICE_SYMLINK_RECURSIVE: {
            ds.symlink_recursive = 1;
            break;
        }
        case DEVICE_SQL_IDENTIFIER: {

            device_pair_t *pair = apr_pcalloc(ds.pool, sizeof(device_pair_t));

            pair->type = DEVICE_PAIR_SQL_IDENTIFIER;
            pair->key = optarg;
            pair->suffix = DEVICE_SQL_SUFFIX;
            pair->optional = optional;
            pair->flag = flag;
            pair->unset = unset;
            pair->q.min = sqlid_min;
            pair->q.max = sqlid_max;

            apr_hash_set(ds.pairs, optarg, APR_HASH_KEY_STRING, pair);

            flag = NULL;
            unset = NULL;

            break;
        }
        case DEVICE_SQL_DELIMITED_IDENTIFIER: {

            device_pair_t *pair = apr_pcalloc(ds.pool, sizeof(device_pair_t));

            pair->type = DEVICE_PAIR_SQL_DELIMITED_IDENTIFIER;
            pair->key = optarg;
            pair->suffix = DEVICE_TXT_SUFFIX;
            pair->optional = optional;
            pair->flag = flag;
            pair->unset = unset;
            pair->q.min = sqlid_min;
            pair->q.max = sqlid_max;

            apr_hash_set(ds.pairs, optarg, APR_HASH_KEY_STRING, pair);

            flag = NULL;
            unset = NULL;

            break;
        }
        case DEVICE_SQL_IDENTIFIER_MIN: {

            status = device_parse_uint64(&ds, optarg, &sqlid_min);
            if (APR_SUCCESS != status) {
                exit(2);
            }

            break;
        }
        case DEVICE_SQL_IDENTIFIER_MAX: {

            status = device_parse_uint64(&ds, optarg, &sqlid_max);
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
            pair->flag = flag;
            pair->unset = unset;
            pair->u.groups = ds.user_groups;

            apr_hash_set(ds.pairs, optarg, APR_HASH_KEY_STRING, pair);

            ds.user_groups = NULL;
            flag = NULL;
            unset = NULL;

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
            pair->flag = flag;
            pair->unset = unset;

            apr_hash_set(ds.pairs, optarg, APR_HASH_KEY_STRING, pair);

            flag = NULL;
            unset = NULL;

            break;
        }
        case DEVICE_RELATION: {

            device_pair_t *pair = apr_pcalloc(ds.pool, sizeof(device_pair_t));

            pair->type = DEVICE_PAIR_RELATION;
            pair->key = optarg;
            pair->suffix = DEVICE_DIR_SUFFIX;
            pair->optional = optional;
            pair->flag = flag;
            pair->unset = unset;
            pair->r.bases = ds.relation_bases;
            pair->r.relation_name = ds.relation_name;
            pair->r.relation_name_len = ds.relation_name_len;
            pair->r.relation_prefix = ds.relation_prefix;
            pair->r.relation_prefix_len = ds.relation_prefix_len;
            pair->r.relation_suffix = ds.relation_suffix;
            pair->r.relation_suffix_len = ds.relation_suffix_len;

            apr_hash_set(ds.pairs, optarg, APR_HASH_KEY_STRING, pair);

            ds.relation_bases = NULL;
            flag = NULL;
            unset = NULL;

            break;
        }
        case DEVICE_RELATION_BASE: {

            const char **base;

            if (!ds.relation_bases) {
                ds.relation_bases = apr_array_make(ds.pool, 2, sizeof(const char *));
            }
            base = apr_array_push(ds.relation_bases);
            base[0]= optarg;

            break;
        }
        case DEVICE_RELATION_NAME: {
            ds.relation_name = optarg;
            ds.relation_name_len = strlen(optarg);
            break;
        }
        case DEVICE_RELATION_SUFFIX: {
            ds.relation_suffix = optarg;
            ds.relation_suffix_len = strlen(optarg);
            break;
        }
        case DEVICE_POLAR: {

            device_pair_t *pair = apr_pcalloc(ds.pool, sizeof(device_pair_t));

            pair->type = DEVICE_PAIR_POLAR;
            pair->key = optarg;
            pair->suffix = DEVICE_ENABLED_SUFFIX;
            pair->optional = optional;
            pair->flag = flag;
            pair->unset = unset;
            pair->p.polar_default = polar_default;

            apr_hash_set(ds.pairs, optarg, APR_HASH_KEY_STRING, pair);

            flag = NULL;
            unset = NULL;

            break;
        }
        case DEVICE_POLAR_DEFAULT: {

            if (!strcmp(optarg, "yes")) {
                polar_default = DEVICE_IS_YES;
            }
            else if (!strcmp(optarg, "no")) {
                polar_default = DEVICE_IS_NO;
            }
            else {
                apr_file_printf(ds.err, "argument '%s': is not 'yes' or 'no'.\n",
                        apr_pescape_echo(ds.pool, optarg, 1));
                exit(2);
            }

            break;
        }
        case DEVICE_SWITCH: {

            device_pair_t *pair = apr_pcalloc(ds.pool, sizeof(device_pair_t));

            pair->type = DEVICE_PAIR_SWITCH;
            pair->key = optarg;
            pair->suffix = DEVICE_ENABLED_SUFFIX;
            pair->optional = optional;
            pair->flag = flag;
            pair->unset = unset;
            pair->sw.switch_default = switch_default;

            apr_hash_set(ds.pairs, optarg, APR_HASH_KEY_STRING, pair);

            flag = NULL;
            unset = NULL;

            break;
        }
        case DEVICE_SWITCH_DEFAULT: {

            if (!strcmp(optarg, "on")) {
                switch_default = DEVICE_IS_ON;
            }
            else if (!strcmp(optarg, "off")) {
                switch_default = DEVICE_IS_OFF;
            }
            else {
                apr_file_printf(ds.err, "argument '%s': is not 'on' or 'off'.\n",
                        apr_pescape_echo(ds.pool, optarg, 1));
                exit(2);
            }

            break;
        }
        case DEVICE_INTEGER: {

            device_pair_t *pair = apr_pcalloc(ds.pool, sizeof(device_pair_t));

            pair->type = DEVICE_PAIR_INTEGER;
            pair->key = optarg;
            pair->suffix = DEVICE_TXT_SUFFIX;
            pair->optional = optional;
            pair->flag = flag;
            pair->unset = unset;
            pair->i.min = integer_min;
            pair->i.max = integer_max;

            apr_hash_set(ds.pairs, optarg, APR_HASH_KEY_STRING, pair);

            flag = NULL;
            unset = NULL;

            break;
        }
        case DEVICE_INTEGER_MIN: {

            status = device_parse_int64(&ds, optarg, &integer_min);
            if (APR_SUCCESS != status) {
                exit(2);
            }

            break;
        }
        case DEVICE_INTEGER_MAX: {

            status = device_parse_int64(&ds, optarg, &integer_max);
            if (APR_SUCCESS != status) {
                exit(2);
            }

            break;
        }
        case DEVICE_HEX: {

            device_pair_t *pair = apr_pcalloc(ds.pool, sizeof(device_pair_t));

            pair->type = DEVICE_PAIR_HEX;
            pair->key = optarg;
            pair->suffix = DEVICE_TXT_SUFFIX;
            pair->optional = optional;
            pair->flag = flag;
            pair->unset = unset;
            pair->h.min = hex_min;
            pair->h.max = hex_max;
            pair->h.cs = hex_case;
            pair->h.width = hex_width;

            apr_hash_set(ds.pairs, optarg, APR_HASH_KEY_STRING, pair);

            flag = NULL;
            unset = NULL;

            break;
        }
        case DEVICE_HEX_MIN: {

            status = device_parse_hex64(&ds, optarg, &hex_min);
            if (APR_SUCCESS != status) {
                exit(2);
            }

            break;
        }
        case DEVICE_HEX_MAX: {

            status = device_parse_hex64(&ds, optarg, &hex_max);
            if (APR_SUCCESS != status) {
                exit(2);
            }

            break;
        }
        case DEVICE_HEX_CASE: {

            if (!strcmp(optarg, "lower")) {
                hex_case = DEVICE_IS_LOWER;
            }
            else if (!strcmp(optarg, "upper")) {
                hex_case = DEVICE_IS_UPPER;
            }
            else {
                apr_file_printf(ds.err, "argument '%s': is not 'lower' or 'upper'.\n",
                        apr_pescape_echo(ds.pool, optarg, 1));
                exit(2);
            }

            break;
        }
        case DEVICE_HEX_WIDTH: {

            status = device_parse_int64(&ds, optarg, &hex_width);
            if (APR_SUCCESS != status) {
                exit(2);
            }

            if (hex_width > DEVICE_HEX_WIDTH_MAX) {
                apr_file_printf(ds.err, "argument '%s': is larger than %d.\n",
                        apr_pescape_echo(ds.pool, optarg, 1), DEVICE_HEX_WIDTH_MAX);
                exit(2);
            }

            if (hex_width < 0) {
                apr_file_printf(ds.err, "argument '%s': is less than zero.\n",
                        apr_pescape_echo(ds.pool, optarg, 1));
                exit(2);
            }

            break;
        }
        case DEVICE_TEXT: {

            device_pair_t *pair = apr_pcalloc(ds.pool, sizeof(device_pair_t));

            pair->type = DEVICE_PAIR_TEXT;
            pair->key = optarg;
            pair->suffix = DEVICE_TXT_SUFFIX;
            pair->optional = optional;
            pair->flag = flag;
            pair->unset = unset;
            pair->t.format = text_format;
            pair->t.min = text_min;
            pair->t.max = text_max;

            apr_hash_set(ds.pairs, optarg, APR_HASH_KEY_STRING, pair);

            flag = NULL;
            unset = NULL;

            break;
        }
        case DEVICE_TEXT_MIN: {

            status = device_parse_uint64(&ds, optarg, &text_min);
            if (APR_SUCCESS != status) {
                exit(2);
            }

            break;
        }
        case DEVICE_TEXT_MAX: {

            status = device_parse_uint64(&ds, optarg, &text_max);
            if (APR_SUCCESS != status) {
                exit(2);
            }

            break;
        }
        case DEVICE_TEXT_FORMAT: {

            text_format = optarg;

            break;
        }
        case DEVICE_URL_PATH: {

            device_pair_t *pair = apr_pcalloc(ds.pool, sizeof(device_pair_t));

            pair->type = DEVICE_PAIR_URL_PATH;
            pair->key = optarg;
            pair->suffix = DEVICE_TXT_SUFFIX;
            pair->optional = optional;
            pair->flag = flag;
            pair->unset = unset;
            pair->up.max = url_path_max;

            apr_hash_set(ds.pairs, optarg, APR_HASH_KEY_STRING, pair);

            flag = NULL;
            unset = NULL;

            break;
        }
        case DEVICE_URL_PATH_ABEMPTY: {

            device_pair_t *pair = apr_pcalloc(ds.pool, sizeof(device_pair_t));

            pair->type = DEVICE_PAIR_URL_PATH_ABEMPTY;
            pair->key = optarg;
            pair->suffix = DEVICE_TXT_SUFFIX;
            pair->optional = optional;
            pair->flag = flag;
            pair->unset = unset;
            pair->up.max = url_path_max;

            apr_hash_set(ds.pairs, optarg, APR_HASH_KEY_STRING, pair);

            flag = NULL;
            unset = NULL;

            break;
        }
        case DEVICE_URL_PATH_ABSOLUTE: {

            device_pair_t *pair = apr_pcalloc(ds.pool, sizeof(device_pair_t));

            pair->type = DEVICE_PAIR_URL_PATH_ABSOLUTE;
            pair->key = optarg;
            pair->suffix = DEVICE_TXT_SUFFIX;
            pair->optional = optional;
            pair->flag = flag;
            pair->unset = unset;
            pair->up.max = url_path_max;

            apr_hash_set(ds.pairs, optarg, APR_HASH_KEY_STRING, pair);

            flag = NULL;
            unset = NULL;

            break;
        }
        case DEVICE_URL_PATH_NOSCHEME: {

            device_pair_t *pair = apr_pcalloc(ds.pool, sizeof(device_pair_t));

            pair->type = DEVICE_PAIR_URL_PATH_NOSCHEME;
            pair->key = optarg;
            pair->suffix = DEVICE_TXT_SUFFIX;
            pair->optional = optional;
            pair->flag = flag;
            pair->unset = unset;
            pair->up.max = url_path_max;

            apr_hash_set(ds.pairs, optarg, APR_HASH_KEY_STRING, pair);

            flag = NULL;
            unset = NULL;

            break;
        }
        case DEVICE_URL_PATH_ROOTLESS: {

            device_pair_t *pair = apr_pcalloc(ds.pool, sizeof(device_pair_t));

            pair->type = DEVICE_PAIR_URL_PATH_ROOTLESS;
            pair->key = optarg;
            pair->suffix = DEVICE_TXT_SUFFIX;
            pair->optional = optional;
            pair->flag = flag;
            pair->unset = unset;
            pair->up.max = url_path_max;

            apr_hash_set(ds.pairs, optarg, APR_HASH_KEY_STRING, pair);

            flag = NULL;
            unset = NULL;

            break;
        }
        case DEVICE_URL_PATH_EMPTY: {

            device_pair_t *pair = apr_pcalloc(ds.pool, sizeof(device_pair_t));

            pair->type = DEVICE_PAIR_URL_PATH_EMPTY;
            pair->key = optarg;
            pair->suffix = DEVICE_TXT_SUFFIX;
            pair->optional = optional;
            pair->flag = flag;
            pair->unset = unset;
            pair->up.max = url_path_max;

            apr_hash_set(ds.pairs, optarg, APR_HASH_KEY_STRING, pair);

            flag = NULL;
            unset = NULL;

            break;
        }
        case DEVICE_URL_PATH_MAX: {

            status = device_parse_uint64(&ds, optarg, &url_path_max);
            if (APR_SUCCESS != status) {
                exit(2);
            }

            break;
        }
        case DEVICE_URI: {

            device_pair_t *pair = apr_pcalloc(ds.pool, sizeof(device_pair_t));

            pair->type = DEVICE_PAIR_URI;
            pair->key = optarg;
            pair->suffix = DEVICE_TXT_SUFFIX;
            pair->optional = optional;
            pair->flag = flag;
            pair->unset = unset;
            pair->uri.schemes = ds.schemes;
            pair->uri.max = uri_max;

            apr_hash_set(ds.pairs, optarg, APR_HASH_KEY_STRING, pair);

            ds.schemes = NULL;
            flag = NULL;
            unset = NULL;

            break;
        }
        case DEVICE_URI_ABSOLUTE: {

            device_pair_t *pair = apr_pcalloc(ds.pool, sizeof(device_pair_t));

            pair->type = DEVICE_PAIR_URI_ABSOLUTE;
            pair->key = optarg;
            pair->suffix = DEVICE_TXT_SUFFIX;
            pair->optional = optional;
            pair->flag = flag;
            pair->unset = unset;
            pair->uri.schemes = ds.schemes;
            pair->uri.max = uri_max;

            apr_hash_set(ds.pairs, optarg, APR_HASH_KEY_STRING, pair);

            ds.schemes = NULL;
            flag = NULL;
            unset = NULL;

            break;
        }
        case DEVICE_URI_RELATIVE: {

            device_pair_t *pair = apr_pcalloc(ds.pool, sizeof(device_pair_t));

            pair->type = DEVICE_PAIR_URI_RELATIVE;
            pair->key = optarg;
            pair->suffix = DEVICE_TXT_SUFFIX;
            pair->optional = optional;
            pair->flag = flag;
            pair->unset = unset;
            pair->uri.schemes = ds.schemes;
            pair->uri.max = uri_max;

            apr_hash_set(ds.pairs, optarg, APR_HASH_KEY_STRING, pair);

            ds.schemes = NULL;
            flag = NULL;
            unset = NULL;

            break;
        }
        case DEVICE_URI_MAX: {

            status = device_parse_uint64(&ds, optarg, &uri_max);
            if (APR_SUCCESS != status) {
                exit(2);
            }

            break;
        }
        case DEVICE_URI_SCHEMES: {

            char *schemes = apr_pstrdup(ds.pool, optarg);
            char *last;

            if (!ds.schemes) {
                ds.schemes = apr_hash_make(ds.pool);
            }

            schemes = apr_strtok(schemes, ", \t", &last);
            do {
                apr_hash_set(ds.schemes, schemes, APR_HASH_KEY_STRING, schemes);
            } while ((schemes = apr_strtok(NULL, ", \t", &last)));

            break;
        }
        case DEVICE_ADDRESS: {

            device_pair_t *pair = apr_pcalloc(ds.pool, sizeof(device_pair_t));

            pair->type = DEVICE_PAIR_ADDRESS;
            pair->key = optarg;
            pair->suffix = DEVICE_TXT_SUFFIX;
            pair->optional = optional;
            pair->flag = flag;
            pair->unset = unset;
            pair->a.max = address_max;
            pair->a.noquotes = address_noquotes;
            pair->a.filesafe = address_filesafe;

            apr_hash_set(ds.pairs, optarg, APR_HASH_KEY_STRING, pair);

            address_max = DEVICE_ADDRESS_MAX_DEFAULT;
            address_noquotes = DEVICE_ADDRESS_NOQUOTES_DEFAULT;
            address_filesafe = DEVICE_ADDRESS_FILESAFE_DEFAULT;
            flag = NULL;
            unset = NULL;

            break;
        }
        case DEVICE_ADDRESS_MAILBOX: {

            device_pair_t *pair = apr_pcalloc(ds.pool, sizeof(device_pair_t));

            pair->type = DEVICE_PAIR_ADDRESS_MAILBOX;
            pair->key = optarg;
            pair->suffix = DEVICE_TXT_SUFFIX;
            pair->optional = optional;
            pair->flag = flag;
            pair->unset = unset;
            pair->a.max = address_max;
            pair->a.noquotes = address_noquotes;
            pair->a.filesafe = address_filesafe;

            apr_hash_set(ds.pairs, optarg, APR_HASH_KEY_STRING, pair);

            address_max = DEVICE_ADDRESS_MAX_DEFAULT;
            address_noquotes = DEVICE_ADDRESS_NOQUOTES_DEFAULT;
            address_filesafe = DEVICE_ADDRESS_FILESAFE_DEFAULT;
            flag = NULL;
            unset = NULL;

            break;
        }
        case DEVICE_ADDRESS_ADDRSPEC: {

            device_pair_t *pair = apr_pcalloc(ds.pool, sizeof(device_pair_t));

            pair->type = DEVICE_PAIR_ADDRESS_ADDRSPEC;
            pair->key = optarg;
            pair->suffix = DEVICE_TXT_SUFFIX;
            pair->optional = optional;
            pair->flag = flag;
            pair->unset = unset;
            pair->a.max = address_max;
            pair->a.noquotes = address_noquotes;
            pair->a.filesafe = address_filesafe;

            apr_hash_set(ds.pairs, optarg, APR_HASH_KEY_STRING, pair);

            address_max = DEVICE_ADDRESS_MAX_DEFAULT;
            address_noquotes = DEVICE_ADDRESS_NOQUOTES_DEFAULT;
            address_filesafe = DEVICE_ADDRESS_FILESAFE_DEFAULT;
            flag = NULL;
            unset = NULL;

            break;
        }
        case DEVICE_ADDRESS_LOCALPART: {

            device_pair_t *pair = apr_pcalloc(ds.pool, sizeof(device_pair_t));

            pair->type = DEVICE_PAIR_ADDRESS_LOCALPART;
            pair->key = optarg;
            pair->suffix = DEVICE_TXT_SUFFIX;
            pair->optional = optional;
            pair->flag = flag;
            pair->unset = unset;
            pair->a.max = address_max;
            pair->a.noquotes = address_noquotes;
            pair->a.filesafe = address_filesafe;

            apr_hash_set(ds.pairs, optarg, APR_HASH_KEY_STRING, pair);

            address_max = DEVICE_ADDRESS_MAX_DEFAULT;
            address_noquotes = DEVICE_ADDRESS_NOQUOTES_DEFAULT;
            address_filesafe = DEVICE_ADDRESS_FILESAFE_DEFAULT;
            flag = NULL;
            unset = NULL;

            break;
        }
        case DEVICE_ADDRESS_MAX: {

            status = device_parse_uint64(&ds, optarg, &address_max);
            if (APR_SUCCESS != status) {
                exit(2);
            }

            break;
        }
        case DEVICE_ADDRESS_NOQUOTES: {

            if (!strcmp(optarg, "yes")) {
                address_noquotes = 1;
            }
            else if (!strcmp(optarg, "no")) {
                address_noquotes = 0;
            }
            else {
                apr_file_printf(ds.err, "argument '%s': is not 'yes' or 'no'.\n",
                        apr_pescape_echo(ds.pool, optarg, 1));
                exit(2);
            }

            break;
        }
        case DEVICE_ADDRESS_FILESAFE: {

            if (!strcmp(optarg, "yes")) {
                address_filesafe = 1;
            }
            else if (!strcmp(optarg, "no")) {
                address_filesafe = 0;
            }
            else {
                apr_file_printf(ds.err, "argument '%s': is not 'yes' or 'no'.\n",
                        apr_pescape_echo(ds.pool, optarg, 1));
                exit(2);
            }

            break;
        }
        case DEVICE_FLAG: {

            flag = optarg;

            break;
        }
        case DEVICE_SHOW_INDEX: {

            show_index = optarg;

            break;
        }
        case DEVICE_SHOW_FLAGS: {

            show_flags = optarg;

            break;
        }
        case DEVICE_SHOW_TABLE: {

            show_table = optarg;

            break;
        }
        case DEVICE_COMMAND: {

            if (APR_SUCCESS != apr_tokenize_to_argv(optarg, &ds.argv, ds.pool)) {
                apr_file_printf(ds.err, "command '%s': cannot be tokenised.\n",
                        apr_pescape_echo(ds.pool, optarg, 1));
                exit(2);
            }

            if (!ds.argv[0]) {
                apr_file_printf(ds.err, "command '%s': cannot be empty.\n",
                        apr_pescape_echo(ds.pool, optarg, 1));
                exit(2);
            }

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

    ds.show_table = apr_array_make(ds.pool, 16, sizeof(device_table_t));

    if (show_table) {

        char *token = apr_pstrdup(ds.pool, show_table);
        char *last;
        device_pair_t *pair;
        device_table_t *entry;

        for (token = apr_strtok(token, ",", &last);
             token;
             token = apr_strtok(NULL, ",", &last)) {

            pair = apr_hash_get(ds.pairs, token, APR_HASH_KEY_STRING);

            if (!pair) {
                return help(ds.err, argv[0],
                        apr_psprintf(ds.pool,
                                "The --show-table contained unknown name '%s'.",
                                token), EXIT_FAILURE, cmdline_opts);
            }

            entry = apr_array_push(ds.show_table);
            entry->pair = pair;
            entry->max = strlen(pair->key);

        }
    }

    ds.show_flags = apr_array_make(ds.pool, 16, sizeof(device_table_t));

    if (show_flags) {

        char *token = apr_pstrdup(ds.pool, show_flags);
        char *last;
        device_pair_t *pair;
        device_table_t *entry;

        for (token = apr_strtok(token, ",", &last);
             token;
             token = apr_strtok(NULL, ",", &last)) {

            pair = apr_hash_get(ds.pairs, token, APR_HASH_KEY_STRING);

            if (!pair) {
                return help(ds.err, argv[0],
                        apr_psprintf(ds.pool,
                                "The --show-flags contained unknown name '%s'.",
                                token), EXIT_FAILURE, cmdline_opts);
            }

            entry = apr_array_push(ds.show_flags);
            entry->pair = pair;
            entry->max = 0;

        }
    }

    ds.show_index = apr_array_make(ds.pool, 16, sizeof(device_table_t));

    if (show_index) {

        char *token = apr_pstrdup(ds.pool, show_index);
        char *last;
        device_pair_t *pair;
        device_table_t *entry;

        for (token = apr_strtok(token, ",", &last);
             token;
             token = apr_strtok(NULL, ",", &last)) {

            pair = apr_hash_get(ds.pairs, token, APR_HASH_KEY_STRING);

            if (!pair) {
                return help(ds.err, argv[0],
                        apr_psprintf(ds.pool,
                                "The --show-index contained unknown name '%s'.",
                                token), EXIT_FAILURE, cmdline_opts);
            }

            entry = apr_array_push(ds.show_index);
            entry->pair = pair;
            entry->max = 0;

        }
    }

    if (ds.key) {

        index = apr_hash_get(ds.pairs, ds.key, APR_HASH_KEY_STRING);
        if (index) {

            /* index parameter always required */
            index->optional = DEVICE_IS_REQUIRED;

            /* mark the index */
            index->index = DEVICE_IS_INDEXED;

            /* index must be unique until further notice */
            index->unique = DEVICE_IS_UNIQUE;

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

            if (ds.mode == DEVICE_RENAME) {
                return help(ds.err, argv[0], "The --rename parameter was not found on the command line.",
                        EXIT_FAILURE, cmdline_opts);
            }

            if (ds.mode == DEVICE_SET) {
                return help(ds.err, argv[0], "The --set parameter was not found on the command line.",
                        EXIT_FAILURE, cmdline_opts);
            }
        }
    }

    if (ds.mode == DEVICE_EXEC && !complete) {
        if (!ds.argv) {
            return help(ds.err, argv[0], "The --command parameter was not found on the command line.",
                    EXIT_FAILURE, cmdline_opts);
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
    else if (ds.mode == DEVICE_RENAME) {

        status = device_rename(&ds, opt->argv + opt->ind);

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
    else if (ds.mode == DEVICE_REINDEX) {

        status = device_reindex(&ds, opt->argv + opt->ind);

        if (APR_SUCCESS != status) {
            exit(1);
        }
    }
    else if (ds.mode == DEVICE_SHOW) {

        status = device_show(&ds, opt->argv + opt->ind);

        if (APR_SUCCESS != status) {
            exit(1);
        }
    }
    else if (ds.mode == DEVICE_EXEC) {

        status = device_exec(&ds, opt->argv + opt->ind);

        if (APR_SUCCESS != status) {
            exit(1);
        }
    }
    else if (ds.mode == DEVICE_LIST) {

        status = device_list(&ds, opt->argv + opt->ind);

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
