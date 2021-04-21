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
 * device - the device shell
 *
 */

#include <stdlib.h>
#include <string.h>

#include <apr_file_io.h>
#include <apr_file_info.h>
#include <apr_general.h>
#include <apr_getopt.h>
#include <apr_lib.h>
#include <apr_network_io.h>
#include <apr_strings.h>
#include <apr_thread_proc.h>

#include "config.h"
#include "device.h"
#include "device_argv.h"
#include "device_compgen.h"
#include "device_editline.h"
#include "device_linenoise.h"
#include "device_read.h"
#include "device_replxx.h"
#include "device_libedit.h"

#define DEVICE_PATHEXT "PATHEXT"
#define DEVICE_ENV_EDITLINE "DEVICE_EDITLINE"
#define DEVICE_PKGLIBEXECDIR "DEVICE_LIBEXEC"
#define DEFAULT_PKGLIBEXECDIR PKGLIBEXECDIR
#define DEVICE_PKGSYSCONFDIR "DEVICE_SYSCONF"
#define DEFAULT_PKGSYSCONFDIR PKGSYSCONFDIR

#define DEVICE_COMPLINE "COMP_LINE"
#define DEVICE_COMMANDLINE "COMMAND_LINE"
#define DEVICE_COMPPOINT "COMP_POINT"

enum lines {
    DEVICE_PREFER_NONE,
    DEVICE_PREFER_REPLXX,
    DEVICE_PREFER_EDITLINE,
    DEVICE_PREFER_LIBEDIT,
    DEVICE_PREFER_LINENOISE,
    DEVICE_PREFER_ARGV,
    DEVICE_PREFER_COMPGEN
};

static const apr_getopt_option_t
    cmdline_opts[] =
{
    /* commands */
    { "help", 'h', 0, "  -h, --help\t\t\tDisplay this help message." },
    { "version", 'v', 0,
        "  -v, --version\t\t\tDisplay the version number." },
    { "file", 'f', 1, "  -f, --file\t\t\tInput file, if not stdin." },
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
            "  %s - Device shell.\n"
            "\n"
            "SYNOPSIS\n"
            "  %s [-v] [-h] [-f file] [commands ...]\n"
            "\n"
            "DESCRIPTION\n"
            "  The device shell allows declarative configuration of a system through an\n"
            "  interactive interface. If a file is provided, configuration is read from\n"
            "  the file.\n"
            "\n"
            "OPTIONS\n", msg ? msg : "", n, n);

    while (opts[i].name) {
        apr_file_printf(out, "%s\n\n", opts[i].description);
        i++;
    }

    apr_file_printf(out,
            "RETURN VALUE\n"
            "  The device shell returns a non zero exit code if the configuration cannot\n"
            "  be read.\n"
            "\n"
            "EXAMPLES\n"
            "  In this example, pass a configuration to the shell.\n"
            "\n"
            "\t~$ echo \"\" | device\n"
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

/* extended form of apr_tokenize_to_argv() */
apr_status_t device_tokenize_to_argv(const char *arg_str, const char ***argv_out,
        device_offset_t **argo_out, device_tokenize_state_t **state_out,
        device_tokenize_state_t *state, const char **err_out, apr_pool_t *pool)
{
    char **argv;
    device_offset_t *argo = NULL;
    const char *cp;
    char *cc = NULL;
    const char *error = NULL;
    device_tokenize_state_t *states = NULL;
    device_tokenize_state_t st;
    unsigned int *offset = NULL;
    int numargs = 0, argnum;
    int length;

#define SKIP_WHITESPACE(cp) \
    for ( ; apr_isspace(*cp); ) { \
        cp++; \
    };

/* HEX_TO_NIBBLE:
 * Convert a character representing a hex encoded 0-9, A-F or a-f and
 * convert it to a 4 bit nibble.
 */
#define HEX_TO_NIBBLE(cp,error) \
        (*cp >= '0' && *cp <= '9') ? *cp - '0' : \
        (*cp >= 'A' && *cp <= 'F') ? *cp - 'A' + 10 : \
        (*cp >= 'a' && *cp <= 'f') ? *cp - 'a' + 10 : \
        (!(error = cp))        /* last line of macro... */

/*
 * OCTAL_TO_3BITS:
 * Convert a character 0 through 7 as an octal character, and convert
 * it to 3 bits.
 */
#define OCTAL_TO_3BITS(cp,error) \
        (*cp >= '0' && *cp <= '7') ? *cp - '0' : \
        (!(error = cp))        /* last line of macro... */


    *state_out = states = apr_pcalloc(pool,
            (strlen(arg_str) + 1) * sizeof(device_tokenize_state_t));

    memcpy(&st, state, sizeof(*state));

    cp = arg_str;
    SKIP_WHITESPACE(cp);

    /* This is ugly and expensive, but if anyone wants to figure a
     * way to support any number of args without counting and
     * allocating, please go ahead and change the code.
     *
     * Must account for the trailing NULL arg.
     */

    /* first question - how many tokens? */
    numargs = 1;
    while (*cp != '\0' && !error) {

/* DETERMINE_NEXTTOKEN:
 * At exit, cp will point to one of the following:  NULL, SPACE, TAB, NEWLINE,
 * CARRIAGE_RETURN.
 * NULL implies the argument string has been fully traversed.
 *
 * If error is not NULL, error will point at the character that generated the
 * error.
 */
#define DETERMINE_NEXTTOKEN(arg_str,cp,cc,offset,state,convert,length,error) \
        {int skip = 0; \
        length = 0; \
        error = NULL; \
        state->intoken = DEVICE_TOKEN_INSIDE; \
        for ( ; *cp != '\0'; cp++) { \
            char ch; \
            ch = *cp; \
            switch (state->escaped) { \
            case DEVICE_TOKEN_NOESCAPE: /* no/was escape mode */ \
            case DEVICE_TOKEN_WASESCAPE: \
                state->escaped = DEVICE_TOKEN_NOESCAPE; \
                switch (state->isquoted) { \
                case DEVICE_TOKEN_NOQUOTE: /* no/was quote */ \
                case DEVICE_TOKEN_WASQUOTE: \
                    state->isquoted = DEVICE_TOKEN_NOQUOTE; \
                    switch (ch) { \
                    case '"': \
                        state->isquoted = DEVICE_TOKEN_DOUBLEQUOTE; \
                        break; \
                    case '\'': \
                        state->isquoted = DEVICE_TOKEN_SINGLEQUOTE; \
                        break; \
                    case '\\': \
                        state->escaped = DEVICE_TOKEN_ESCAPE_SLASH; /* handle ansi c */ \
                        break; \
                    case ' ': \
                    case '\t': \
                    case '\n': \
                    case '\f': \
                    case '\r': \
                        state->intoken = DEVICE_TOKEN_OUTSIDE; \
                        skip = 1; /* end of token found, time to leave */ \
                        break; \
                    default: \
                        if (convert) { \
                            *cc++ = ch; \
                            if (offset) *offset++ = (cp - arg_str); \
                        } \
                        length++; \
                        break; \
                    }; \
                    break; \
                case DEVICE_TOKEN_DOUBLEQUOTE: /* double quote */ \
                    switch (ch) { \
                    case '"': \
                        state->isquoted = DEVICE_TOKEN_WASQUOTE; \
                        break; \
                    case '\\': \
                        state->escaped = DEVICE_TOKEN_ESCAPE_SLASH; /* handle ansi c */ \
                        break; \
                    default: \
                        if (convert) { \
                            *cc++ = ch; \
                            if (offset) *offset++ = (cp - arg_str); \
                        } \
                        length++; \
                        break; \
                    }; \
                    break; \
                case DEVICE_TOKEN_SINGLEQUOTE: /* single quote */ \
                    switch (ch) { \
                    case '\'': \
                        state->isquoted = DEVICE_TOKEN_WASQUOTE; \
                        break; \
                    default: \
                        if (convert) { \
                            *cc++ = ch; \
                            if (offset) *offset++ = (cp - arg_str); \
                        } \
                        length++; \
                        break; \
                    }; \
                    break; \
                } \
                break; \
            case DEVICE_TOKEN_ESCAPE_SLASH: /* seen \ */ \
                switch (ch) { \
                case 'a': /* \a bell */ \
                    if (convert) { \
                        *cc++ = '\a'; \
                        if (offset) *offset++ = (cp - arg_str); \
                    } \
                    length++; \
                    state->escaped = DEVICE_TOKEN_WASESCAPE; \
                    break; \
                case 'b': /* \b backspace */ \
                    if (convert) { \
                        *cc++ = '\b'; \
                        if (offset) *offset++ = (cp - arg_str); \
                    } \
                    length++; \
                    state->escaped = DEVICE_TOKEN_WASESCAPE; \
                    break; \
                case 'c': /* \c control character */ \
                    state->escaped = DEVICE_TOKEN_ESCAPE_CONTROL; \
                    break; \
                case 'e': /* \e escape */ \
                    if (convert) { \
                        *cc++ = '\e'; \
                        if (offset) *offset++ = (cp - arg_str); \
                    } \
                    length++; \
                    state->escaped = DEVICE_TOKEN_WASESCAPE; \
                    break; \
                case 'f': /* \f form feed */ \
                    if (convert) { \
                        *cc++ = '\f'; \
                        if (offset) *offset++ = (cp - arg_str); \
                    } \
                    length++; \
                    state->escaped = DEVICE_TOKEN_WASESCAPE; \
                    break; \
                case 'n': /* \n new line */ \
                    if (convert) { \
                        *cc++ = '\n'; \
                        if (offset) *offset++ = (cp - arg_str); \
                    } \
                    length++; \
                    state->escaped = DEVICE_TOKEN_WASESCAPE; \
                    break; \
                case 'r': /* \n carriage return */ \
                    if (convert) { \
                        *cc++ = '\r'; \
                        if (offset) *offset++ = (cp - arg_str); \
                    } \
                    length++; \
                    state->escaped = DEVICE_TOKEN_WASESCAPE; \
                    break; \
                case 't': /* \n horizontal tab */ \
                    if (convert) { \
                        *cc++ = '\t'; \
                        if (offset) *offset++ = (cp - arg_str); \
                    } \
                    length++; \
                    state->escaped = DEVICE_TOKEN_WASESCAPE; \
                    break; \
                case 'v': /* \v vertical tab */ \
                    if (convert) { \
                        *cc++ = '\v'; \
                        if (offset) *offset++ = (cp - arg_str); \
                    } \
                    length++; \
                    state->escaped = DEVICE_TOKEN_WASESCAPE; \
                    break; \
                case '\\': /* \\ slash */ \
                    if (convert) { \
                        *cc++ = '\\'; \
                        if (offset) *offset++ = (cp - arg_str); \
                    } \
                    length++; \
                    state->escaped = DEVICE_TOKEN_WASESCAPE; \
                    break; \
                case '\'': /* \' single quote */ \
                    if (convert) { \
                        *cc++ = '\''; \
                        if (offset) *offset++ = (cp - arg_str); \
                    } \
                    length++; \
                    state->escaped = DEVICE_TOKEN_WASESCAPE; \
                    break; \
                case '"': /* \" double quote */ \
                    if (convert) { \
                        *cc++ = '"'; \
                        if (offset) *offset++ = (cp - arg_str); \
                    } \
                    length++; \
                    state->escaped = DEVICE_TOKEN_WASESCAPE; \
                    break; \
                case '?': /* \? question mark */ \
                    if (convert) { \
                        *cc++ = '\?'; \
                        if (offset) *offset++ = (cp - arg_str); \
                    } \
                    length++; \
                    state->escaped = DEVICE_TOKEN_WASESCAPE; \
                    break; \
                case '0': \
                case '1': \
                case '2': \
                case '3': /* \nnn octal number */ \
                    if (convert) { \
                        *cc = (OCTAL_TO_3BITS(cp,error)) << 6; /* no advance */ \
                    } \
                    else { \
                        OCTAL_TO_3BITS(cp,error); \
                    } \
                    state->escaped = DEVICE_TOKEN_ESCAPE_OCTAL2; \
                    break; \
                case 'x': /* \x hex byte */ \
                    state->escaped = DEVICE_TOKEN_ESCAPE_HEX1; \
                    break; \
                case 'u': /* \u 16 bit unicode */ \
                    state->escaped = DEVICE_TOKEN_ESCAPE_UTF16_1; \
                    break; \
                case 'U': /* \U 32 bit unicode */ \
                    state->escaped = DEVICE_TOKEN_ESCAPE_UTF32_1; \
                    break; \
                default: /* unknown character, error */ \
                    error = cp; \
                    break; \
                }; \
                break; \
            case DEVICE_TOKEN_ESCAPE_OCTAL2: /* seen \[0-3][0-7] (octal) */ \
                if (convert) { \
                    *cc |= (OCTAL_TO_3BITS(cp,error)) << 3; /* no advance */ \
                } \
                else { \
                    OCTAL_TO_3BITS(cp,error); \
                } \
                state->escaped = DEVICE_TOKEN_ESCAPE_OCTAL3; \
                break; \
            case DEVICE_TOKEN_ESCAPE_OCTAL3: /* seen \[0-3][0-7][0-7] (octal) */ \
                if (convert) { \
                    *cc++ |= (OCTAL_TO_3BITS(cp,error)); /* advance */ \
                    if (offset) *offset++ = (cp - arg_str); \
                } \
                else { \
                    OCTAL_TO_3BITS(cp,error); \
                } \
                length++; \
                state->escaped = DEVICE_TOKEN_WASESCAPE; \
                break; \
            case DEVICE_TOKEN_ESCAPE_HEX1: /* seen \x[H] (hex) */ \
                if (convert) { \
                    *cc = (HEX_TO_NIBBLE(cp,error)) << 4; /* no advance */ \
                } \
                else { \
                    HEX_TO_NIBBLE(cp,error); \
                } \
                state->escaped = DEVICE_TOKEN_ESCAPE_HEX2; \
                break; \
            case DEVICE_TOKEN_ESCAPE_HEX2: /* seen \x[HH] (hex) */ \
                if (convert) { \
                    *cc++ |= (HEX_TO_NIBBLE(cp,error)); /* advance */ \
                    if (offset) *offset++ = (cp - arg_str); \
                } \
                else { \
                    HEX_TO_NIBBLE(cp,error); \
                } \
                length++; \
                state->escaped = DEVICE_TOKEN_WASESCAPE; \
                break; \
            case DEVICE_TOKEN_ESCAPE_UTF16_1: /* seen \u[H] (16 bit unicode) */ \
                if (convert) { \
                    *cc = (HEX_TO_NIBBLE(cp,error)) << 4; /* no advance */ \
                } \
                else { \
                    HEX_TO_NIBBLE(cp,error); \
                } \
                state->escaped = DEVICE_TOKEN_ESCAPE_UTF16_2; \
                break; \
            case DEVICE_TOKEN_ESCAPE_UTF16_2: /* seen \u[HH] (16 bit unicode) */ \
                if (convert) { \
                    *cc++ |= (HEX_TO_NIBBLE(cp,error)); /* advance */ \
                    if (offset) *offset++ = (cp - arg_str); \
                } \
                else { \
                    HEX_TO_NIBBLE(cp,error); \
                } \
                length++; \
                state->escaped = DEVICE_TOKEN_ESCAPE_UTF16_3; \
                break; \
            case DEVICE_TOKEN_ESCAPE_UTF16_3: /* seen \u[HHH] (16 bit unicode) */ \
                if (convert) { \
                    *cc = (HEX_TO_NIBBLE(cp,error)) << 4; /* no advance */ \
                } \
                else { \
                    HEX_TO_NIBBLE(cp,error); \
                } \
                state->escaped = DEVICE_TOKEN_ESCAPE_UTF16_4; \
                break; \
            case DEVICE_TOKEN_ESCAPE_UTF16_4: /* seen \u[HHHH] (16 bit unicode) */ \
                if (convert) { \
                    *cc++ |= (HEX_TO_NIBBLE(cp,error)); /* advance */ \
                    if (offset) *offset++ = (cp - arg_str); \
                } \
                else { \
                    HEX_TO_NIBBLE(cp,error); \
                } \
                length++; \
                state->escaped = DEVICE_TOKEN_WASESCAPE; \
                break; \
            case DEVICE_TOKEN_ESCAPE_UTF32_1: /* seen \U[H] (32 bit unicode) */ \
                if (convert) { \
                    *cc = (HEX_TO_NIBBLE(cp,error)) << 4; /* no advance */ \
                } \
                else { \
                    HEX_TO_NIBBLE(cp,error); \
                } \
                state->escaped = DEVICE_TOKEN_ESCAPE_UTF32_2; \
                break; \
            case DEVICE_TOKEN_ESCAPE_UTF32_2: /* seen \U[HH] (32 bit unicode) */ \
                if (convert) { \
                    *cc++ |= (HEX_TO_NIBBLE(cp,error)); /* advance */ \
                    if (offset) *offset++ = (cp - arg_str); \
                } \
                else { \
                    HEX_TO_NIBBLE(cp,error); \
                } \
                length++; \
                state->escaped = DEVICE_TOKEN_ESCAPE_UTF32_3; \
                break; \
            case DEVICE_TOKEN_ESCAPE_UTF32_3: /* seen \U[HHH] (32 bit unicode) */ \
                if (convert) { \
                    *cc = (HEX_TO_NIBBLE(cp,error)) << 4; /* no advance */ \
                } \
                else { \
                    HEX_TO_NIBBLE(cp,error); \
                } \
                state->escaped = DEVICE_TOKEN_ESCAPE_UTF32_4; \
                break; \
            case DEVICE_TOKEN_ESCAPE_UTF32_4: /* seen \U[HHHH] (32 bit unicode) */ \
                if (convert) { \
                    *cc++ |= (HEX_TO_NIBBLE(cp,error)); /* advance */ \
                    if (offset) *offset++ = (cp - arg_str); \
                } \
                else { \
                    HEX_TO_NIBBLE(cp,error); \
                } \
                length++; \
                state->escaped = DEVICE_TOKEN_ESCAPE_UTF32_5; \
                break; \
            case DEVICE_TOKEN_ESCAPE_UTF32_5: /* seen \U[H] (32 bit unicode) */ \
                if (convert) { \
                    *cc = (HEX_TO_NIBBLE(cp,error)) << 4; /* no advance */ \
                } \
                else { \
                    HEX_TO_NIBBLE(cp,error); \
                } \
                state->escaped = DEVICE_TOKEN_ESCAPE_UTF32_6; \
                break; \
            case DEVICE_TOKEN_ESCAPE_UTF32_6: /* seen \U[HH] (32 bit unicode) */ \
                if (convert) { \
                    *cc++ |= (HEX_TO_NIBBLE(cp,error)); /* advance */ \
                    if (offset) *offset++ = (cp - arg_str); \
                } \
                else { \
                    HEX_TO_NIBBLE(cp,error); \
                } \
                length++; \
                state->escaped = DEVICE_TOKEN_ESCAPE_UTF32_7; \
                break; \
            case DEVICE_TOKEN_ESCAPE_UTF32_7: /* seen \U[HHH] (32 bit unicode) */ \
                if (convert) { \
                    *cc = (HEX_TO_NIBBLE(cp,error)) << 4; /* no advance */ \
                } \
                else { \
                    HEX_TO_NIBBLE(cp,error); \
                } \
                state->escaped = DEVICE_TOKEN_ESCAPE_UTF32_8; \
                break; \
            case DEVICE_TOKEN_ESCAPE_UTF32_8: /* seen \U[HHHH] (32 bit unicode) */ \
                if (convert) { \
                    *cc++ |= (HEX_TO_NIBBLE(cp,error)); /* advance */ \
                    if (offset) *offset++ = (cp - arg_str); \
                } \
                else { \
                    HEX_TO_NIBBLE(cp,error); \
                } \
                length++; \
                state->escaped = DEVICE_TOKEN_WASESCAPE; \
                break; \
            case DEVICE_TOKEN_ESCAPE_CONTROL: \
                switch (ch) { \
                case '@': /* null */ \
                case 'A': /* start of heading */ \
                case 'B': /* start  of text */ \
                case 'C': /* end of text */ \
                case 'D': /* end of transmit */ \
                case 'E': /* enquiry */ \
                case 'F': /* ack */ \
                case 'G': /* bell */ \
                case 'H': /* backspace */ \
                case 'I': /* horizontal tab */ \
                case 'J': /* linefeed */ \
                case 'K': /* vertical tab */ \
                case 'L': /* form feed */ \
                case 'M': /* carriage return */ \
                case 'N': /* shift out */ \
                case 'O': /* shift in */ \
                case 'P': /* data line escape */ \
                case 'Q': /* device control 1 */ \
                case 'R': /* device control 2 */ \
                case 'S': /* device control 3 */ \
                case 'T': /* device control 4 */ \
                case 'U': /* nack */ \
                case 'V': /* sync idel */ \
                case 'W': /* end of transmit block */ \
                case 'X': /* cancel */ \
                case 'Y': /* end of medium */ \
                case 'Z': /* substitute */ \
                case '[': /* escape */ \
                case '\\': /* file separator */ \
                case ']': /* group separator */ \
                case '^': /* record separator */ \
                case '_': /* unit separator */ \
                    if (convert) { \
                        switch (ch) { \
                        case '@': /* null */ \
                            *cc++ = '\x00'; \
                            break; \
                        case 'A': /* start of heading */ \
                            *cc++ = '\x01'; \
                            break; \
                        case 'B': /* start  of text */ \
                            *cc++ = '\x02'; \
                            break; \
                        case 'C': /* end of text */ \
                            *cc++ = '\x03'; \
                            break; \
                        case 'D': /* end of transmit */ \
                            *cc++ = '\x04'; \
                            break; \
                        case 'E': /* enquiry */ \
                            *cc++ = '\x05'; \
                            break; \
                        case 'F': /* ack */ \
                            *cc++ = '\x06'; \
                            break; \
                        case 'G': /* bell */ \
                            *cc++ = '\x07'; \
                            break; \
                        case 'H': /* backspace */ \
                            *cc++ = '\x08'; \
                            break; \
                        case 'I': /* horizontal tab */ \
                            *cc++ = '\x09'; \
                            break; \
                        case 'J': /* linefeed */ \
                            *cc++ = '\x0A'; \
                            break; \
                        case 'K': /* vertical tab */ \
                            *cc++ = '\x0B'; \
                            break; \
                        case 'L': /* form feed */ \
                            *cc++ = '\x0C'; \
                            break; \
                        case 'M': /* carriage return */ \
                            *cc++ = '\x0D'; \
                            break; \
                        case 'N': /* shift out */ \
                            *cc++ = '\x0E'; \
                            break; \
                        case 'O': /* shift in */ \
                            *cc++ = '\x0F'; \
                            break; \
                        case 'P': /* data line escape */ \
                            *cc++ = '\x10'; \
                            break; \
                        case 'Q': /* device control 1 */ \
                            *cc++ = '\x11'; \
                            break; \
                        case 'R': /* device control 2 */ \
                            *cc++ = '\x12'; \
                            break; \
                        case 'S': /* device control 3 */ \
                            *cc++ = '\x13'; \
                            break; \
                        case 'T': /* device control 4 */ \
                            *cc++ = '\x24'; \
                            break; \
                        case 'U': /* nack */ \
                            *cc++ = '\x25'; \
                            break; \
                        case 'V': /* sync idel */ \
                            *cc++ = '\x26'; \
                            break; \
                        case 'W': /* end of transmit block */ \
                            *cc++ = '\x27'; \
                            break; \
                        case 'X': /* cancel */ \
                            *cc++ = '\x28'; \
                            break; \
                        case 'Y': /* end of medium */ \
                            *cc++ = '\x29'; \
                            break; \
                        case 'Z': /* substitute */ \
                            *cc++ = '\x2A'; \
                            break; \
                        case '[': /* escape */ \
                            *cc++ = '\x2B'; \
                            break; \
                        case '\\': /* file separator */ \
                            *cc++ = '\x2C'; \
                            break; \
                        case ']': /* group separator */ \
                            *cc++ = '\x2D'; \
                            break; \
                        case '^': /* record separator */ \
                            *cc++ = '\x2E'; \
                            break; \
                        case '_': /* unit separator */ \
                            *cc++ = '\x2F'; \
                            break; \
                        } \
                        if (offset) *offset++ = (cp - arg_str); \
                    } \
                    length++; \
                    state->escaped = DEVICE_TOKEN_WASESCAPE; \
                    break; \
                default: /* unknown character, error */ \
                    error = cp; \
                    break; \
                }; \
                break; \
            default: /* unknown escape state, error */ \
                error = cp; \
                break; \
            }; \
            if (convert) { \
                memcpy(states++, state, sizeof(*state)); \
            } \
            if (skip || error) { \
                break; \
            } \
        } \
        if (convert) { \
            if (offset) *offset++ = (cp - arg_str); /* FIXME check this offset? */ \
        }}        /* last line of macro... */

        DETERMINE_NEXTTOKEN(arg_str,cp,cc,offset,(&st),0,length,error)

        if (error) {
            *err_out = error;
            return APR_EINVAL;
        }

        SKIP_WHITESPACE(cp);

        numargs++;
    }

    argv = apr_pcalloc(pool, numargs * sizeof(char*));
    *argv_out = (const char **)argv;
    if (argo_out) {
        argo = apr_pcalloc(pool, numargs * sizeof(device_offset_t));
        *argo_out = argo;
    }

    memcpy(&st, state, sizeof(*state));

    // use ct instead
    cp = arg_str;
    SKIP_WHITESPACE(cp);

    /* second question - how long is each token? */
    for (argnum = 0; argnum < (numargs-1); argnum++) {

        int start = cp - arg_str;

        DETERMINE_NEXTTOKEN(arg_str,cp,cc,offset,(&st),0,length,error)

        argv[argnum] = apr_palloc(pool, length + 1);
        if (argo_out) {
            argo[argnum].offsets = apr_palloc(pool, (length + 1) * sizeof(unsigned int));
            argo[argnum].size = length + 1;
            argo[argnum].start = start;
            argo[argnum].end = cp - arg_str;
        }

        argv[argnum][length] = 0;

        SKIP_WHITESPACE(cp);

    }

    memcpy(&st, state, sizeof(*state));

    cp = arg_str;
    SKIP_WHITESPACE(cp);

    /*  let's munch on those tokens */
    for (argnum = 0; argnum < (numargs-1); argnum++) {

        cc = argv[argnum];
        if (argo_out) {
            offset = argo[argnum].offsets;
        }

        DETERMINE_NEXTTOKEN(arg_str,cp,cc,offset,(&st),1,length,error)

        SKIP_WHITESPACE(cp);

    }

    memcpy(state, &st, sizeof(*state));

    argv[argnum] = NULL;

    return APR_SUCCESS;
}

apr_array_header_t *device_parse_pathext(apr_pool_t *pool, const char *pathext)
{
    apr_array_header_t *exts;
    int count = 0;

    if (pathext) {
        int i = 0;
        while (pathext[i]) {
            if (pathext[i] == ';') {
                count++;
            }
            i++;
        }
        if (i > 0 && pathext[i - 1] != ';') {
            count++;
        }
    }

    exts = apr_array_make(pool, count, sizeof(device_name_t));

    if (pathext) {
        device_name_t *name;
        const char *slider;

        while ((slider = strchr(pathext, ';'))) {
            device_name_t *name = apr_array_push(exts);
            name->size = slider - pathext;
            name->name = apr_pstrndup(pool, pathext, name->size);
            pathext = slider + 1;
        }

        name = apr_array_push(exts);
        name->size = strlen(pathext);
        name->name = apr_pstrndup(pool, pathext, name->size);
    }

    return exts;
}

void device_is_executable(apr_finfo_t *dirent,
        apr_array_header_t *exts, apr_array_header_t *names)
{
    device_name_t *name;
    int i;

    for (i = 0; i < exts->nelts; i++)
    {
        const device_name_t *ext = &APR_ARRAY_IDX(exts, i, const device_name_t);
        int len = strlen(dirent->name);
        int size = ext->size;

        if (len > size && !strncasecmp(dirent->name, ext->name, size)) {

            name = apr_array_push(names);
            name->size = len - size;
            name->name = apr_pstrndup(names->pool, dirent->name, name->size);

            return;
        }
    }

    if ((dirent->protection & (APR_FPROT_WREAD | APR_FPROT_WEXECUTE))
            == (APR_FPROT_WREAD | APR_FPROT_WEXECUTE)) {

        name = apr_array_push(names);
        name->size = strlen(dirent->name);
        name->name = apr_pstrndup(names->pool, dirent->name, name->size);
    }

}

const device_name_t* device_find_name(apr_array_header_t *names, const char *search)
{
    int i;

    for (i = 0; names && i < names->nelts; i++)
    {
        device_name_t *name = &APR_ARRAY_IDX(names, i, device_name_t);

        if (!strcmp(name->name, search)) {
            return name;
        }
    }

    return NULL;
}

int device_find_prefix(apr_array_header_t *names, const char *search,
        const device_name_t **recent)
{
    int i;
    apr_size_t len =  strlen(search);
    int count = 0;

    for (i = 0; names && i < names->nelts; i++)
    {
        device_name_t *name = &APR_ARRAY_IDX(names, i, device_name_t);

        if (!strncmp(name->name, search, len)) {
            if (recent) {
                *recent = name;
            }
            count++;
        }
    }

    return count;
}

int device_find_prefixes(apr_array_header_t *names, const char *search,
        apr_array_header_t *results, char **common)
{
    int i;
    apr_size_t len =  strlen(search);
    int count = 0;

    for (i = 0; names && i < names->nelts; i++)
    {
        device_name_t *name = &APR_ARRAY_IDX(names, i, device_name_t);

        if (!strncmp(name->name, search, len)) {

            device_name_t *result = apr_array_push(results);

            result->name = name->name;
            result->size = name->size;

            if (*common) {
                const char *buf = name->name + len;
                int j;

                for (j = 0; buf[j] && (*common)[j] && buf[j] == (*common)[j]; j++);

                (*common)[j] = 0;
            }
            else {
                *common = apr_pstrdup(results->pool, name->name + len);
            }

            count++;
        }
    }

    return count;
}

device_parse_t *device_parse_make(apr_pool_t *pool, device_parse_t *parent)
{
    apr_pool_t *pp;
    device_parse_t *nps;

    apr_pool_create(&pp, pool);
    nps = apr_pcalloc(pp, sizeof(device_parse_t));

    nps->pool = pp;
    nps->parent = parent;

    return nps;
}

device_parse_t *device_container_make(apr_pool_t *pool, const char *libexec,
        const char *sysconf, const char *name, device_parse_t *parent,
        apr_array_header_t *pathext)
{
    device_parse_t *dp = device_parse_make(pool, parent);
    apr_dir_t *thedir;
    apr_finfo_t dirent;
    apr_status_t status;

    dp->name = apr_pstrdup(dp->pool, name);
    dp->type = DEVICE_PARSE_CONTAINER;
    dp->c.containers = apr_array_make(dp->pool, 1, sizeof(device_name_t));
    dp->c.commands = apr_array_make(dp->pool, 1, sizeof(device_name_t));
    dp->c.builtins = apr_array_make(dp->pool, 2, sizeof(device_name_t));

    if (parent == NULL) {
        device_name_t *name;

        name = apr_array_push(dp->c.builtins);
        name->size = strlen("exit");
        name->name = apr_pstrndup(dp->c.builtins->pool, "exit", name->size);

        name = apr_array_push(dp->c.builtins);
        name->size = strlen("quit");
        name->name = apr_pstrndup(dp->c.builtins->pool, "quit", name->size);

    }

    if ((apr_filepath_merge(&dp->c.sysconf, sysconf, name, APR_FILEPATH_SECUREROOT | APR_FILEPATH_NATIVE, dp->pool))) {
        return dp;
    }

    if ((apr_filepath_merge(&dp->c.libexec, libexec, name, APR_FILEPATH_SECUREROOT | APR_FILEPATH_NATIVE, dp->pool))) {
        return dp;
    }

    if ((status = apr_dir_open(&thedir, dp->c.libexec, dp->pool)) != APR_SUCCESS) {
        return dp;
    }

    do {
        status = apr_dir_read(&dirent, APR_FINFO_TYPE | APR_FINFO_NAME | APR_FINFO_WPROT, thedir);
        if (APR_STATUS_IS_INCOMPLETE(status)) {
            continue; /* ignore un-stat()able files */
        }
        else if (status != APR_SUCCESS) {
            break;
        }

        /* hidden files are ignored */
        if (dirent.name[0] == '.') {
            continue;
        }

        switch (dirent.filetype) {
        case APR_LNK:
        case APR_REG: {

            device_is_executable(&dirent, pathext, dp->c.commands);

            break;
        }

        case APR_DIR: {

            device_name_t *name = apr_array_push(dp->c.containers);
            name->size = strlen(dirent.name);
            name->name = apr_pstrndup(dp->c.containers->pool, dirent.name, name->size);

            break;
        }
        default:
            continue;
        }

    } while (1);

    apr_dir_close(thedir);

    return dp;
}

device_parse_t* device_command_make(apr_pool_t *pool, const char *libexec,
        char *sysconf, const char *name, device_parse_t *parent,
        apr_array_header_t *pathext)
{
    device_parse_t *dp = device_parse_make(pool, parent);

    dp->name = apr_pstrdup(dp->pool, name);
    dp->type = DEVICE_PARSE_COMMAND;

    if ((apr_filepath_merge(&dp->r.libexec, libexec, name, APR_FILEPATH_SECUREROOT | APR_FILEPATH_NATIVE, dp->pool))) {
        return dp;
    }

    dp->r.sysconf = sysconf;

    return dp;
}

device_parse_t *device_parameter_make(apr_pool_t *pool,
        const char *name, device_parse_t *parent, device_parse_t *command)
{
    device_parse_t *dp = device_parse_make(pool, parent);

    dp->name = apr_pstrdup(dp->pool, name);
    dp->type = DEVICE_PARSE_PARAMETER;
    dp->p.command = command;

    return dp;
}

device_parse_t *device_builtin_make(apr_pool_t *pool,
        const char *name, device_parse_t *parent)
{
    device_parse_t *dp = device_parse_make(pool, parent);

    dp->name = apr_pstrdup(dp->pool, name);
    dp->type = DEVICE_PARSE_BUILTIN;

    return dp;
}

device_parse_t *device_option_make(apr_pool_t *pool,
        const char *name, device_parse_t *parent, device_parse_t *command)
{
    device_parse_t *dp = device_parse_make(pool, parent);

    dp->name = apr_pstrdup(dp->pool, name);
    dp->type = DEVICE_PARSE_OPTION;
    dp->o.command = command;

    return dp;
}

device_parse_t *device_ambiguous_make(apr_pool_t *pool,
        const char *name, device_parse_t *parent)
{
    device_parse_t *dp = device_parse_make(pool, parent);

    dp->name = apr_pstrdup(dp->pool, name);
    dp->type = DEVICE_PARSE_AMBIGUOUS;
    dp->a.containers = apr_array_make(dp->pool, 1, sizeof(device_name_t));
    dp->a.commands = apr_array_make(dp->pool, 1, sizeof(device_name_t));
    dp->a.builtins = apr_array_make(dp->pool, 2, sizeof(device_name_t));

    return dp;
}

static const char **device_environment_make(device_t *d)
{
    apr_array_header_t *env = apr_array_make(d->tpool, 2, sizeof(const char *));

#define DEVICE_ENVIRON_ADD(env,var) \
    { \
        const char *entry; \
        if ((entry = getenv(var))) { \
            const char **e = apr_array_push(env); \
            *e = apr_psprintf(d->tpool, "%s=%s", var, entry);  \
        } \
    }        /* last line of macro... */

    /*
     * Pass a sanitised list of variables from the environment.
     *
     * No PATH = we don't want anything outside device affecting the
     * binaries being executed.
     *
     * No EDITOR/PAGER, as these could have callout capabilities and
     * we must avoid that.
     */

    DEVICE_ENVIRON_ADD(env, "TERM")
    DEVICE_ENVIRON_ADD(env, "LANG")
    DEVICE_ENVIRON_ADD(env, "LC_ALL")
    DEVICE_ENVIRON_ADD(env, "TMPDIR")
    DEVICE_ENVIRON_ADD(env, "TZ")
    DEVICE_ENVIRON_ADD(env, "USER")

    apr_array_push(env);

    return (const char **)env->elts;
}

apr_status_t device_parse(device_t *d, const char *arg,
        device_offset_t *offset, device_parse_t *parent, device_parse_t **result)
{
    const device_name_t *name;

    /* no args or empty args, leave in one piece */
    if (!arg) {
        return APR_EINVAL;
    }

    switch (parent->type) {

    /* parent is a container */
    case DEVICE_PARSE_CONTAINER: {

        const device_name_t *bname = NULL;
        const device_name_t *cname = NULL;
        const device_name_t *rname = NULL;

        int matches;

        /* handle parent match */
        if (!strcmp(arg, "..")) {
            if (parent->parent) {
                *result = parent->parent;
            }
            else {
                return APR_EABOVEROOT;
            }
        }

        /* handle exact matches */
        else if ((name = device_find_name(parent->c.builtins, arg))) {
            *result = device_builtin_make(parent->pool, name->name, parent);
        }
        else if ((name = device_find_name(parent->c.commands, arg))) {
            *result = device_command_make(parent->pool, parent->c.libexec,
                    parent->c.sysconf, name->name, parent, d->pathext);
        }
        else if ((name = device_find_name(parent->c.containers, arg))) {
            *result = device_container_make(parent->pool, parent->c.libexec,
                    parent->c.sysconf, name->name, parent, d->pathext);
        }

        /* handle prefix matches with exactly one result */
        else if (1 == (matches = device_find_prefix(parent->c.builtins, arg, &bname) +
                   device_find_prefix(parent->c.commands, arg, &rname) +
                   device_find_prefix(parent->c.containers, arg, &cname))) {

            if (bname) {
                *result = device_builtin_make(parent->pool, bname->name, parent);
            }
            else if (rname) {
                *result = device_command_make(parent->pool, parent->c.libexec,
                        parent->c.sysconf, rname->name, parent, d->pathext);
            }
            else if (cname) {
                *result = device_container_make(parent->pool, parent->c.libexec,
                        parent->c.sysconf, cname->name, parent, d->pathext);
            }
            else {
                /* theoretically not possible */
                return APR_EGENERAL;
            }

        }

        /* handle ambiguous results */
        else if (1 < matches) {

            char *common = NULL;

            *result = device_ambiguous_make(parent->pool, arg, parent);

            device_find_prefixes(parent->c.builtins, arg, (*result)->a.builtins, &common);
            device_find_prefixes(parent->c.commands, arg, (*result)->a.commands, &common);
            device_find_prefixes(parent->c.containers, arg, (*result)->a.containers, &common);

            (*result)->a.prefix = apr_pstrdup((*result)->pool, arg);
            (*result)->a.common = common;
        }

        /* handle no results */
        else {
            return APR_ENOENT;
        }

        break;
    }
    case DEVICE_PARSE_COMMAND: {

        *result = device_parameter_make(parent->pool, arg,
                parent, parent);

        break;
    }
    case DEVICE_PARSE_PARAMETER: {

        *result = device_parameter_make(parent->pool, arg,
                parent, parent->p.command);

        break;
    }
    case DEVICE_PARSE_BUILTIN: {

        *result = device_builtin_make(parent->pool, arg,
                parent);

        break;
    }
    case DEVICE_PARSE_OPTION: {

        *result = device_option_make(parent->pool, arg,
                parent, parent->o.command);

        break;
    }
    case DEVICE_PARSE_AMBIGUOUS: {

        /* by definition, nothing can be found under an ambiguous parent */
        return APR_ENOENT;
    }
    }

    /* did we successfully parse the command? */

    if (offset) {
        (*result)->offset = offset;
    }

    return APR_SUCCESS;
}

apr_status_t device_colourise(device_t *d, const char **args,
        device_offset_t *offsets, device_tokenize_state_t state, device_parse_t **result,
        apr_pool_t **pool)
{
    device_parse_t *first, *current;
    int i;
    int root = 0;
    apr_status_t status;

    /* detect a comment, and ignore if so */
    if (*args && (*args)[0] == '#') {
        *result = NULL;
        return APR_SUCCESS;
    }

    /* go back to the root, forget any previous state */
    if (*args && (*args)[0] == '/') {
        root = 1;
    }

    /* special case - first element just a slash? skip if so */
    if (root && (*args)[1] == 0) {
        args++;
        if (offsets) {
            offsets++;
        }
    }

    /* initialise the root level */
    first = current = device_container_make(d->pool, d->libexec, d->sysconf, NULL, NULL, d->pathext);

    /* walk the saved path */
    for (i = 0; !root && d->args && i < d->args->nelts; i++)
    {
        const char *arg = APR_ARRAY_IDX(d->args, i, const char *);

        if (APR_SUCCESS != (status = device_parse(d, arg, NULL, current, &current))) {

            /* no complete */
            apr_pool_destroy(first->pool);
            return status;
        }

    }

    /* walk the command line */
    while (*args) {

        const char *arg = *args;

        /* handle the root slash */
        if (root) {
            arg++;
            root = 0;
            if (offsets) {
                offsets++;
            }
        }

        if (APR_SUCCESS != (status =
                device_parse(d, arg, offsets, current, &current))) {

            /* this is as far as we can go, ignore everything past this*/
            break;
        }

        args++;
        if (offsets) {
            offsets++;
        }
    }

    *result = current;
    *pool = first->pool;

    return APR_SUCCESS;
}

apr_status_t device_complete(device_t *d, const char **args,
        device_offset_t *offsets, device_tokenize_state_t state, device_parse_t **result,
        apr_pool_t **pool)
{
    device_parse_t *first, *current;
    int i;
    int root = 0;
    apr_status_t status;

    /* detect a comment, and ignore if so */
    if (*args && (*args)[0] == '#') {
        *result = NULL;
        return APR_SUCCESS;
    }

    /* go back to the root, forget any previous state */
    if (*args && (*args)[0] == '/') {
        root = 1;
    }

    /* special case - first element just a slash? skip if so */
    if (root && (*args)[1] == 0) {
        args++;
        if (offsets) {
            offsets++;
        }
    }

    /* initialise the root level */
    first = current = device_container_make(d->pool, d->libexec, d->sysconf, NULL, NULL, d->pathext);

    /* walk the saved path */
    for (i = 0; !root && d->args && i < d->args->nelts; i++)
    {
        const char *arg = APR_ARRAY_IDX(d->args, i, const char *);

        if (APR_SUCCESS != (status = device_parse(d, arg, NULL, current, &current))) {

            /* no complete */
            apr_pool_destroy(first->pool);
            return status;
        }

    }

    /* walk the command line */
    while (*args) {

        const char *arg = *args;

        /* handle the root slash */
        if (root) {
            arg++;
            root = 0;
            if (offsets) {
                offsets++;
            }
        }

        if (APR_SUCCESS != (status =
                device_parse(d, arg, offsets, current, &current))) {

            /* no complete */
            apr_pool_destroy(first->pool);
            return status;
        }

        args++;
        if (offsets) {
            offsets++;
        }
    }

    /* was the last character outside a token? */
    if (state.intoken == DEVICE_TOKEN_OUTSIDE) {

        if (APR_SUCCESS != (status = device_parse(d, "", NULL, current, &current))) {

            apr_pool_destroy(first->pool);
            return status;
        }

    }

    *result = current;
    *pool = first->pool;

    return APR_SUCCESS;
}

apr_status_t device_command(device_t *d, const char **args,
        device_offset_t *offsets, apr_size_t line)
{
    device_parse_t *first, *current, *parent;
    int i;
    int root = 0;
    apr_status_t status;

    /* no args or empty args, leave in one piece */
    if (!args || !*args) {
        return APR_SUCCESS;
    }

    /* detect a comment, and ignore if so */
    if ((*args)[0] == '#') {
        return APR_SUCCESS;
    }

    /* go back to the root, forget any previous state */
    if ((*args)[0] == '/') {
        root = 1;
    }

    /* special case - first element just a slash? skip if so */
    if (root && (*args)[1] == 0) {
        args++;
        if (offsets) {
            offsets++;
        }
    }

    /* initialise the root level */
    first = current = device_container_make(d->pool, d->libexec, d->sysconf, NULL, NULL, d->pathext);

    /* walk the saved path */
    for (i = 0; !root && d->args && i < d->args->nelts; i++)
    {
        const char *arg = APR_ARRAY_IDX(d->args, i, const char *);

        if (APR_SUCCESS != (status = device_parse(d, arg, NULL, current, &current))) {

            apr_file_printf(d->err, "bad saved command\n");
            apr_pool_destroy(first->pool);
            return status;
        }

    }

    /* walk the command line */
    while (*args) {

        const char *arg = *args;

        /* handle the root slash */
        if (root) {
            arg++;
            root = 0;
        }

        /* parse the token */
        if (APR_SUCCESS != (status =
                device_parse(d, arg, offsets, current, &current))) {

            if (offsets) {
                apr_file_printf(d->err, "bad command '%s' (line %" APR_SIZE_T_FMT
                        " column %u)\n", arg, line + 1, (offsets->start) + 1);
            }
            else {
                apr_file_printf(d->err, "bad command '%s'\n", arg);
            }
            apr_pool_destroy(first->pool);
            return status;
        }

        args++;
        if (offsets) {
            offsets++;
        }
    }

    /* where did we land? */
    switch (current->type) {
    case DEVICE_PARSE_CONTAINER: {

        apr_pool_t *pool;
        int count = 0;

        if (d->args) {
            apr_pool_destroy(d->args->pool);
        }

        apr_pool_create(&pool, d->pool);

        parent = current->parent;
        while (parent) {
            count++;
            parent = parent->parent;
        }

        d->args = apr_array_make(pool, count, sizeof(const char *));

        parent = current->parent;
        while (parent) {
            parent = parent->parent;
            apr_array_push(d->args);
        }

        while (count) {

            count--;

            (APR_ARRAY_IDX(d->args, count, const char *)) =
                    apr_pstrdup(pool, current->name);

            current = current->parent;
        }

        break;
    }
    case DEVICE_PARSE_COMMAND:
    case DEVICE_PARSE_PARAMETER: {

        device_parse_t *command;
        apr_array_header_t *argv;
        apr_procattr_t *procattr;
        apr_proc_t *proc;
        const char **arg;
        apr_finfo_t finfo;
        int count = 0;
        int i;

        /* go back and find the command */
        command = current;
        while (command->type != DEVICE_PARSE_COMMAND) {
            count++;
            command = command->parent;
        }

        /* go forward, create the arguments */
        argv = apr_array_make(first->pool, count + 3, sizeof(const char *));

        arg = apr_array_push(argv);
        *arg = command->r.libexec;

        arg = apr_array_push(argv);
        *arg = "--";

        for (i = 0; i < count; i++) {
            apr_array_push(argv);
        }
        apr_array_push(argv);

        while (count) {

            count--;

            (APR_ARRAY_IDX(argv, (count + 2), const char *)) = current->name;

            current = current->parent;
        }

        /* sanity check - is sysconf a directory? */
        if ((status = apr_stat(&finfo, command->r.sysconf, APR_FINFO_TYPE, command->pool))) {
            apr_file_printf(d->err, "cannot stat sysconfdir: %pm\n", &status);
            break;
        }
        else if (finfo.filetype != APR_DIR) {
            apr_file_printf(d->err, "sysconfdir not a directory\n");
            break;
        }

        if ((status = apr_procattr_create(&procattr, first->pool)) != APR_SUCCESS) {
            apr_file_printf(d->err, "cannot create procattr: %pm\n", &status);
            break;
        }

        if ((status = apr_procattr_child_in_set(procattr, d->in, NULL)) != APR_SUCCESS) {
            apr_file_printf(d->err, "cannot set stdin: %pm\n", &status);
            break;
        }

        if ((status = apr_procattr_child_out_set(procattr, d->out, NULL)) != APR_SUCCESS) {
            apr_file_printf(d->err, "cannot set stdout: %pm\n", &status);
            break;
        }

        if ((status = apr_procattr_child_err_set(procattr, d->err, NULL)) != APR_SUCCESS) {
            apr_file_printf(d->err, "cannot set stdout: %pm\n", &status);
            break;
        }

//        if ((status = apr_procattr_io_set(procattr, APR_FULL_BLOCK, APR_FULL_BLOCK,
//                                APR_FULL_BLOCK)) != APR_SUCCESS) {
//            apr_file_printf(d->err, "cannot set io procattr: %pm\n", &status);
//            break;
//        }

        if ((status = apr_procattr_dir_set(procattr, command->r.sysconf))
                != APR_SUCCESS) {
            apr_file_printf(d->err, "cannot set directory in procattr: %pm\n", &status);
            break;
        }

        if ((status = apr_procattr_cmdtype_set(procattr, APR_PROGRAM)) != APR_SUCCESS) {
            apr_file_printf(d->err, "cannot set command type in procattr: %pm\n", &status);
            break;
        }

        proc = apr_pcalloc(first->pool, sizeof(apr_proc_t));
        if ((status = apr_proc_create(proc, command->r.libexec, (const char* const*) argv->elts,
                device_environment_make(d), procattr, first->pool)) != APR_SUCCESS) {
            apr_file_printf(d->err, "cannot run command: %pm\n", &status);
            break;
        }

        if ((status = apr_proc_wait(proc, NULL, NULL, APR_WAIT)) != APR_CHILD_DONE) {
            apr_file_printf(d->err, "cannot wait for command: %pm\n", &status);
            break;
        }

        break;
    }
    case DEVICE_PARSE_BUILTIN:
    case DEVICE_PARSE_OPTION: {

        apr_array_header_t *argv;
        const char *arg;
        int count = 1;
        int i;

        parent = current;
        while (parent->type != DEVICE_PARSE_BUILTIN) {
            count++;
            parent = parent->parent;
        }

        argv = apr_array_make(first->pool, count, sizeof(const char *));

        for (i = 0; i < count; i++) {
            apr_array_push(argv);
        }
        apr_array_push(argv);

        while (count) {

            count--;

            (APR_ARRAY_IDX(argv, count, const char *)) = arg = current->name;

            current = current->parent;
        }

        /* special commands, do we want to leave? */
        if (current->parent == NULL && (!strcmp(arg, "quit") ||
                !strcmp(arg, "exit"))) {

            apr_pool_destroy(first->pool);

            return APR_EOF;
        }

        break;
    }
    case DEVICE_PARSE_AMBIGUOUS: {

        if (offsets) {
            apr_file_printf(d->err, "bad command '%s' (line %" APR_SIZE_T_FMT
                    " column %d)\n", current->name, line + 1, current->offset->start + 1);
        }
        else {
            apr_file_printf(d->err, "bad command '%s'\n", current->name);
        }

        apr_pool_destroy(first->pool);

        return APR_ENOENT;
    }
    }

    apr_pool_destroy(first->pool);

    return APR_SUCCESS;
}

int main(int argc, const char * const argv[])
{
    device_t d = { 0 };

    char str[MAXHOSTNAMELEN + 1];

    apr_status_t status;
    apr_getopt_t *opt;
    const char *optarg;
    const char *editline = getenv(DEVICE_ENV_EDITLINE);
    const char *libexec = getenv(DEVICE_PKGLIBEXECDIR);
    const char *sysconf = getenv(DEVICE_PKGSYSCONFDIR);
    const char *pathext = getenv(DEVICE_PATHEXT);
    const char *compline = getenv(DEVICE_COMPLINE);
    const char *commandline = getenv(DEVICE_COMMANDLINE);
    const char *comppoint = getenv(DEVICE_COMPPOINT);
    const char *file = NULL;
    const char *line = NULL;

    int optch;
    int rc;
    int lines = DEVICE_PREFER_NONE;

    /* lets get APR off the ground, and make sure it terminates cleanly */
    if (APR_SUCCESS != (status = apr_app_initialize(&argc, &argv, NULL))) {
        return 1;
    }
    atexit(apr_terminate);

    if (APR_SUCCESS != (status = apr_pool_create_ex(&d.pool, NULL, abortfunc, NULL))) {
        return 1;
    }

    if (APR_SUCCESS != (status = apr_pool_create(&d.tpool, d.pool))) {
        return 1;
    }

    apr_file_open_stderr(&d.err, d.pool);
    apr_file_open_stdin(&d.in, d.pool);
    apr_file_open_stdout(&d.out, d.pool);

    d.pathext = device_parse_pathext(d.pool, pathext);

    if (!(d.user = getenv("USER"))) {
        d.user = "(unknown)";
    }

    if (apr_gethostname(str, sizeof(str) - 1, d.pool) != APR_SUCCESS) {
        apr_file_printf(d.err, "%s: could not read the servername.\n", argv[0]);
        d.hostname = "localhost";
    }
    else {
        d.hostname = apr_pstrdup(d.pool, str);
    }

    if (!libexec) {
        libexec = PKGLIBEXECDIR;
    }
    d.libexec = libexec;

    if (!sysconf) {
        sysconf = PKGSYSCONFDIR;
    }
    d.sysconf = sysconf;

    line = compline ? compline : commandline;
    if (line && comppoint) {
        int c = atoi(comppoint);
        if (c >= 0 && c <= strlen(line)) {
            line = apr_pstrndup(d.pool, line, c);
        }
    }

    apr_getopt_init(&opt, d.pool, argc, argv);
    while ((status = apr_getopt_long(opt, cmdline_opts, &optch, &optarg))
            == APR_SUCCESS) {

        switch (optch) {
        case 'v': {
            version(d.out);
            return 0;
        }
        case 'h': {
            help(d.out, argv[0], NULL, 0, cmdline_opts);
            return 0;
        }
        case 'f': {
            file = optarg;
            break;
        }
        }

    }
    if (APR_SUCCESS != status && APR_EOF != status) {
        return help(d.err, argv[0], NULL, EXIT_FAILURE, cmdline_opts);
    }

    /* set up default behaviour */
#ifdef HAVE_LINENOISE_H
    lines = DEVICE_PREFER_LINENOISE;
#endif
#ifdef HAVE_HISTEDIT_H
    /* we prefer libedit if not replxx */
    lines = DEVICE_PREFER_LIBEDIT;
#endif
#ifdef HAVE_EDITLINE_H
    /* we prefer editline if not replxx */
    lines = DEVICE_PREFER_EDITLINE;
#endif
#ifdef HAVE_REPLXX_H
    /* we prefer replxx by default */
    lines = DEVICE_PREFER_REPLXX;
#endif

    /* prefer completion */
    if (line) {
        lines = DEVICE_PREFER_COMPGEN;
    }

    /* origin is command line */
    else if ((argc - opt->ind)) {
        lines = DEVICE_PREFER_ARGV;
    }

    /* override the default based on the environment */
    else if (editline) {
#ifdef HAVE_HISTEDIT_H
        if (!strcmp(editline, DEVICE_LIBEDIT)) {
            lines = DEVICE_PREFER_LIBEDIT;
        }
#endif
#ifdef HAVE_EDITLINE_H
        if (!strcmp(editline, DEVICE_EDITLINE)) {
            lines = DEVICE_PREFER_EDITLINE;
        }
#endif
#ifdef HAVE_REPLXX_H
        if (!strcmp(editline, DEVICE_REPLXX)) {
            lines = DEVICE_PREFER_REPLXX;
        }
#endif
#ifdef HAVE_LINENOISE_H
        if (!strcmp(editline, DEVICE_LINENOISE)) {
            lines = DEVICE_PREFER_LINENOISE;
        }
#endif
    }

    /* read from a file? */
    if (file) {
        if (APR_SUCCESS
                != (status = apr_file_open(&d.in, file, APR_FOPEN_READ,
                        APR_FPROT_OS_DEFAULT, d.pool))) {
            apr_file_printf(d.err,
                    "Could not open file '%s' for read: %pm\n", file, &status);
            apr_pool_destroy(d.pool);
            exit(1);
        }
        lines = DEVICE_PREFER_NONE;
    }

    /* completion? */
    line = getenv("COMP_LINE");
    if (!line) {
        line = getenv("COMMAND_LINE");
    }
    if (line) {
        const char *cpoint = getenv("COMP_POINT");

        /* handle limited line length */
        if (cpoint) {
            int c = atoi(cpoint);
            if (c < strlen(line)) {
                line = apr_pstrndup(d.pool, line, c);
            }
        }

        lines = DEVICE_PREFER_COMPGEN;
    }

    switch (lines) {
#ifdef HAVE_HISTEDIT_H
    case DEVICE_PREFER_LIBEDIT:
        rc = device_libedit(&d, argv[0], stdin, stdout, stderr);
        break;
#endif
#ifdef HAVE_EDITLINE_H
    case DEVICE_PREFER_EDITLINE:
        rc = device_editline(&d, argv[0]);
        break;
#endif
#ifdef HAVE_REPLXX_H
    case DEVICE_PREFER_REPLXX:
        rc = device_replxx(&d);
        break;
#endif
#ifdef HAVE_LINENOISE_H
    case DEVICE_PREFER_LINENOISE:
        rc = device_linenoise(&d);
        break;
#endif
    case DEVICE_PREFER_ARGV:
        rc = device_argv(&d, opt->argv + opt->ind);
        break;
    case DEVICE_PREFER_COMPGEN:
        rc = device_compgen(&d, line);
        break;
    default:
        rc = device_read(&d);
        break;
    }

    apr_pool_destroy(d.pool);

    exit(rc);
}
