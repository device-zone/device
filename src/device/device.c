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

#include <apr.h>
#include <apr_file_io.h>
#include <apr_file_info.h>
#include <apr_general.h>
#include <apr_getopt.h>
#include <apr_lib.h>
#include <apr_network_io.h>
#include <apr_poll.h>
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
#include "device_util.h"

#if HAVE_TERMIOS_H
#include <termios.h>
#endif

#if HAVE_LIBGEN_H
#include <libgen.h>
#endif

#define DEVICE_PATHEXT "PATHEXT"
#define DEVICE_ENV_EDITLINE "DEVICE_EDITLINE"
#define DEVICE_PKGLIBEXECDIR "DEVICE_LIBEXEC"
#define DEFAULT_PKGLIBEXECDIR PKGLIBEXECDIR "/state"
#define DEVICE_PKGSYSCONFDIR "DEVICE_SYSCONF"
#define DEFAULT_PKGSYSCONFDIR PKGSYSCONFDIR
#define DEFAULT_BASE "device"

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
            "  The device shell allows declarative configuration of a system. If commands\n"
            "  are specified, the configuration will be displayed or updated. If no commands\n"
            "  are specified, commands are entered through an interactive interface. If a\n"
            "  file is provided, configuration is read from the file.\n"
            "\n"
            "  Where supported by the shell or interactive interface, tab completion can be\n"
            "  used to discover valid commands and their options.\n"
            "\n"
            "OPTIONS\n", msg ? msg : "", n, n);

    while (opts[i].name) {
        apr_file_printf(out, "%s\n\n", opts[i].description);
        i++;
    }

    apr_file_printf(out,
            "ENVIRONMENT VARIABLES\n"
            "  The following environment variables will modify the behaviour of the device\n"
            "  shell.\n"
            "\n"
            "  " DEVICE_ENV_EDITLINE "\tSet the editline library. Must be one\n\t\t\tof:"
#ifdef HAVE_HISTEDIT_H
                    " " DEVICE_LIBEDIT
#endif
#ifdef HAVE_EDITLINE_H
                    " " DEVICE_EDITLINE
#endif
#ifdef HAVE_REPLXX_H
                    " " DEVICE_REPLXX
#endif
#ifdef HAVE_LINENOISE_H
                    " " DEVICE_LINENOISE
#endif
            "\n"
            "  " DEVICE_PKGLIBEXECDIR "\tLocation of commands and supporting options. Defaults\n\t\t\tto " DEFAULT_PKGLIBEXECDIR ".\n"
            "  " DEVICE_PKGSYSCONFDIR "\tLocation of current configuration. Defaults\n\t\t\tto " DEFAULT_PKGSYSCONFDIR ".\n"

            "\n"
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
    int length, equals;

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


    if (state_out) {
        *state_out = states = apr_pcalloc(pool,
                (strlen(arg_str) + 1) * sizeof(device_tokenize_state_t));
    }

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
#define DETERMINE_NEXTTOKEN(arg_str,cp,cc,offset,state,convert,length,error,equals) \
        {int skip = 0; \
        length = 0; \
        equals = -1; \
        error = NULL; \
        state->intoken = DEVICE_TOKEN_INSIDE; \
        state->equals = DEVICE_TOKEN_NOTSEEN; \
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
                    case '=': \
                        if (state->equals == DEVICE_TOKEN_NOTSEEN) { \
                            state->equals = DEVICE_TOKEN_SEEN; \
                            equals = length; \
                        } \
                        /* no break */ \
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
                case ' ': /* space */ \
                    if (convert) { \
                        *cc++ = ' '; \
                        if (offset) *offset++ = (cp - arg_str); \
                    } \
                    length++; \
                    state->escaped = DEVICE_TOKEN_WASESCAPE; \
                    break; \
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
                if (states) { \
                    memcpy(states++, state, sizeof(*state)); \
                } \
            } \
            if (skip || error) { \
                break; \
            } \
        } \
        if (convert) { \
            if (offset) *offset++ = (cp - arg_str); /* FIXME check this offset? */ \
        }}        /* last line of macro... */

        DETERMINE_NEXTTOKEN(arg_str,cp,cc,offset,(&st),0,length,error,equals)

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

        DETERMINE_NEXTTOKEN(arg_str,cp,cc,offset,(&st),0,length,error,equals)

        argv[argnum] = apr_palloc(pool, length + 1);
        if (argo_out) {
            argo[argnum].offsets = apr_palloc(pool, (length + 1) * sizeof(unsigned int));
            argo[argnum].size = length + 1;
            argo[argnum].start = start;
            argo[argnum].equals = equals;
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

        DETERMINE_NEXTTOKEN(arg_str,cp,cc,offset,(&st),1,length,error,equals)

        SKIP_WHITESPACE(cp);

    }

    memcpy(state, &st, sizeof(*state));

    argv[argnum] = NULL;

    return APR_SUCCESS;
}

#if HAVE_TCGETATTR
static struct termios termios;
#endif

void device_save_termios()
{
#if HAVE_TCGETATTR
    tcgetattr(0, &termios);
#endif
}

void device_restore_termios()
{
#if HAVE_TCGETATTR
    tcsetattr(0, TCSANOW, &termios);
#endif
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

static device_parse_t *device_parse_make(apr_pool_t *pool, device_parse_t *parent)
{
    apr_pool_t *pp;
    device_parse_t *nps;

    apr_pool_create(&pp, pool);
    nps = apr_pcalloc(pp, sizeof(device_parse_t));

    nps->pool = pp;
    nps->parent = parent;

    return nps;
}

device_parse_t *device_ambiguous_make(device_parse_t *dp,
        const char *name)
{
    dp->name = apr_pstrdup(dp->pool, name);
    dp->type = DEVICE_PARSE_AMBIGUOUS;
    dp->a.prefix = NULL;
    dp->a.common = NULL;
    dp->a.containers = apr_array_make(dp->pool, 1, sizeof(device_name_t));
    dp->a.commands = apr_array_make(dp->pool, 1, sizeof(device_name_t));
    dp->a.builtins = apr_array_make(dp->pool, 2, sizeof(device_name_t));
    dp->a.keys = apr_array_make(dp->pool, 1, sizeof(device_name_t));
    dp->a.requires = apr_array_make(dp->pool, 1, sizeof(device_name_t));
    dp->a.values = apr_array_make(dp->pool, 1, sizeof(device_name_t));

    return dp;
}

static device_parse_t *device_container_make(device_parse_t *dp, const char *libexec,
        const char *sysconf, const char *name, apr_array_header_t *pathext)
{
    apr_dir_t *thedir;
    apr_finfo_t dirent;
    apr_status_t status;

    dp->name = apr_pstrdup(dp->pool, name);
    dp->type = DEVICE_PARSE_CONTAINER;
    dp->c.containers = apr_array_make(dp->pool, 1, sizeof(device_name_t));
    dp->c.commands = apr_array_make(dp->pool, 1, sizeof(device_name_t));
    dp->c.builtins = apr_array_make(dp->pool, 2, sizeof(device_name_t));

    if (dp->parent == NULL) {
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

device_parse_t* device_command_make(device_parse_t *dp, const char *libexec,
        char *sysconf, const char *name, apr_array_header_t *pathext)
{
    dp->name = apr_pstrdup(dp->pool, name);
    dp->type = DEVICE_PARSE_COMMAND;

    if ((apr_filepath_merge(&dp->r.libexec, libexec, name, APR_FILEPATH_SECUREROOT | APR_FILEPATH_NATIVE, dp->pool))) {
        return dp;
    }

    dp->r.sysconf = sysconf;

    return dp;
}

static apr_status_t cleanup_realloc(void *dummy)
{
    if (dummy) {
        free(dummy);
    }

    return APR_SUCCESS;
}

typedef enum device_proc_std_e {
    DEVICE_PROC_STDOUT = 1,
    DEVICE_PROC_STDERR = 2,
} device_proc_std_e;

static apr_status_t device_proc_gets(apr_pool_t *pool, apr_proc_t *proc, char *buf,
    apr_size_t *buflen, device_proc_std_e *what)
{
    apr_pool_t *p;
    apr_status_t status;
    apr_pollfd_t pfd = {0};
    apr_pollset_t *pollset;
    apr_size_t len = *buflen;
    int fds_waiting;

    apr_pool_create(&p, pool);

    if (APR_SUCCESS != (status = apr_pollset_create(&pollset, 2, p, 0))) {
        return status;
    }

    fds_waiting = 0;

    pfd.p = pool;
    pfd.desc_type = APR_POLL_FILE;
    pfd.reqevents = APR_POLLIN;

    if (proc->err) {
        pfd.desc.f = proc->err;
        if (APR_SUCCESS != (status = apr_pollset_add(pollset, &pfd))) {
            apr_pool_destroy(p);
            return status;
        }
        fds_waiting++;
    }

    if (proc->out) {
        pfd.desc.f = proc->out;
        if (APR_SUCCESS != (status = apr_pollset_add(pollset, &pfd))) {
            apr_pool_destroy(p);
            return status;
        }
        fds_waiting++;
    }

    while (fds_waiting) {
        int i, num_events;
        const apr_pollfd_t *pdesc;

        status = apr_pollset_poll(pollset, -1, &num_events, &pdesc);
        if (status != APR_SUCCESS && !APR_STATUS_IS_EINTR(status)) {
            break;
        }

        for (i = 0; i < num_events; i++) {

            if (pdesc[i].desc.f == proc->out) {

                status = apr_file_gets(buf, len, proc->out);
                if (APR_STATUS_IS_EOF(status)) {
                    apr_file_close(proc->out);
                    proc->out = NULL;
                    apr_pollset_remove(pollset, &pdesc[i]);
                    --fds_waiting;
                }
                else if (status != APR_SUCCESS) {
                    apr_pool_destroy(p);
                    return status;
                }
                else {
                    *buflen = strlen(buf);
                    apr_pool_destroy(p);
                    *what = DEVICE_PROC_STDOUT;
                    return APR_SUCCESS;
                }

            }

            else if (pdesc[i].desc.f == proc->err) {

                *buflen = len;
                status = apr_file_read(proc->err, buf, buflen);
                if (APR_STATUS_IS_EOF(status)) {
                    apr_file_close(proc->err);
                    proc->err = NULL;
                    apr_pollset_remove(pollset, &pdesc[i]);
                    --fds_waiting;
                }
                else if (status != APR_SUCCESS) {
                    apr_pool_destroy(p);
                    return status;
                }
                else {
                    *what = DEVICE_PROC_STDERR;
                    apr_pool_destroy(p);
                    return APR_SUCCESS;
                }

            }

        }
    }

    apr_pool_destroy(p);
    return APR_EOF;
}

device_parse_t* device_parameter_make(device_parse_t *dp, const char *name,
        device_offset_t *offset, device_parse_t *command, const char **env,
        int completion)
{
    device_parse_t *parent;
    apr_file_t *ioread, *iowrite;
    apr_array_header_t *argv;
    apr_procattr_t *procattr;
    apr_proc_t *proc;
    const char **arg;
    device_name_t *result;
    apr_finfo_t finfo;
    apr_status_t status;
    int skip = 0;
    int count = 0;
    int overflow = DEVICE_MAX_PARAMETERS;
    int exitcode = 0;
    apr_exit_why_e exitwhy = 0;
    int i;


    dp->name = apr_pstrdup(dp->pool, name);
    dp->type = DEVICE_PARSE_PARAMETER;
    dp->p.command = command;
    dp->p.keys = apr_array_make(dp->pool, 1, sizeof(device_name_t));
    dp->p.requires = apr_array_make(dp->pool, 1, sizeof(device_name_t));
    dp->p.values = apr_array_make(dp->pool, 1, sizeof(device_name_t));
    dp->p.error = NULL;
    dp->p.stderr = NULL;
    dp->p.stderrlen = 0;

    if (offset) {
        if (offset->equals > -1) {
            dp->p.key = apr_pstrndup(dp->pool, name, offset->equals);
            dp->p.value = apr_pstrdup(dp->pool, name + offset->equals + 1);
            if (strchr(dp->p.key, '=')) {
                dp->p.error = apr_psprintf(dp->pool,
                        "key contains a hidden equals character.\n");
                return dp;
            }
        }
        else {
            dp->p.value = dp->name;
        }
    }
    else {
        const char *equals;
        if ((equals = strchr(name, '='))) {
            dp->p.key = apr_pstrndup(dp->pool, name, equals - name);
            dp->p.value = apr_pstrdup(dp->pool, equals + 1);
        }
        else {
            dp->p.value = dp->name;
        }
    }

    if (!completion) {
        /* skip the sanity check command */
        return dp;
    }

    /* run the command, make sure it parses */

    /* go back and count the parameters */
    parent = dp->parent;
    while (parent->type == DEVICE_PARSE_PARAMETER) {
        count++;
        parent = parent->parent;
    }

    /* go forward, create the arguments */
    argv = apr_array_make(dp->pool, count * 2 + 4, sizeof(const char *));

    arg = apr_array_push(argv);
    *arg = command->r.libexec;

    arg = apr_array_push(argv);
    *arg = "-c";

    for (i = 0; i < count; i++) {
        apr_array_push(argv);
        apr_array_push(argv);
    }

    parent = dp->parent;
    while (count) {

        count--;

        (APR_ARRAY_IDX(argv, (count * 2 + 2), const char *)) =
                parent->p.key ? parent->p.key :
                        parent->p.value ? parent->p.value : "";

        (APR_ARRAY_IDX(argv, (count * 2 + 3), const char *)) =
                parent->p.key && parent->p.value ? parent->p.value : "";

        parent = parent->parent;
    }

    if (dp->p.key) {
        arg = apr_array_push(argv);
        *arg = dp->p.key;

        arg = apr_array_push(argv);
        *arg = dp->p.value;
    }
    else {
        arg = apr_array_push(argv);
        *arg = dp->name;
    }

    apr_array_push(argv);

    /* sanity check - is sysconf a directory? */
    if ((status = apr_stat(&finfo, command->r.sysconf, APR_FINFO_TYPE, command->pool))) {
        dp->p.error = apr_psprintf(dp->pool, "cannot stat sysconfdir: %pm\n", &status);
        return dp;
    }
    else if (finfo.filetype != APR_DIR) {
        dp->p.error = apr_psprintf(dp->pool, "sysconfdir not a directory\n");
        return dp;
    }

    if ((status = apr_procattr_create(&procattr, dp->pool)) != APR_SUCCESS) {
        dp->p.error = apr_psprintf(dp->pool, "cannot create procattr: %pm\n", &status);
        return dp;
    }

//        if ((status = apr_procattr_detach_set(procattr, 1))
//                != APR_SUCCESS) {
//        dp->p.error = apr_psprintf(dp->pool, "cannot set detached in procattr: %pm\n", &status);
//            break;
//        }


    if ((status = apr_file_pipe_create_ex(&ioread, &iowrite, APR_FULL_BLOCK,
            dp->pool)) != APR_SUCCESS) {
        dp->p.error = apr_psprintf(dp->pool, "cannot create pipes: %pm\n", &status);
        return dp;
    }

//    if ((status = apr_procattr_child_in_set(procattr, NULL, NULL)) != APR_SUCCESS) {
//        dp->p.error = apr_psprintf(dp->pool, "cannot set stdin: %pm\n", &status);
//        return dp;
//    }

    //        if ((status = apr_procattr_child_out_set(procattr, &iowrite, &ioread)) != APR_SUCCESS) {
//    if ((status = apr_procattr_child_out_set(procattr, NULL, NULL)) != APR_SUCCESS) {
//        dp->p.error = apr_psprintf(dp->pool, "cannot set out pipe: %pm\n", &status);
//        return dp;
//    }

//    if ((status = apr_procattr_child_err_set(procattr, NULL, NULL)) != APR_SUCCESS) {
//        dp->p.error = apr_psprintf(dp->pool, "cannot set stderr: %pm\n", &status);
//        return dp;
//    }

    if ((status = apr_procattr_io_set(procattr, APR_CHILD_BLOCK, APR_CHILD_BLOCK,
            APR_CHILD_BLOCK)) != APR_SUCCESS) {
        dp->p.error = apr_psprintf(dp->pool, "cannot set io procattr: %pm\n", &status);
        return dp;
    }

    if ((status = apr_procattr_dir_set(procattr, command->r.sysconf))
            != APR_SUCCESS) {
        dp->p.error = apr_psprintf(dp->pool, "cannot set directory in procattr: %pm\n", &status);
        return dp;
    }

    if ((status = apr_procattr_cmdtype_set(procattr, APR_PROGRAM)) != APR_SUCCESS) {
        dp->p.error = apr_psprintf(dp->pool, "cannot set command type in procattr: %pm\n", &status);
        return dp;
    }

    proc = apr_pcalloc(dp->pool, sizeof(apr_proc_t));
    if ((status = apr_proc_create(proc, command->r.libexec, (const char* const*) argv->elts,
            env, procattr, dp->pool)) != APR_SUCCESS) {
        dp->p.error = apr_psprintf(dp->pool, "cannot run command: %pm\n", &status);
        return dp;
    }

    apr_file_close(proc->in);
    // apr_file_close(proc->err);
    // apr_file_close(proc->out);

    /* read the results */
    while (1) {
        char buf[HUGE_STRING_LEN];
        apr_size_t buflen = sizeof(buf);
        char *val = buf + 1;
        device_proc_std_e what;

        if (APR_SUCCESS == (status = device_proc_gets(dp->pool, proc, buf, &buflen, &what))) {

            /* handle stderr... */
            if (what == DEVICE_PROC_STDERR) {
                dp->p.stderr = realloc(dp->p.stderr, dp->p.stderrlen + buflen);
                memcpy(dp->p.stderr + dp->p.stderrlen, buf, buflen);
                dp->p.stderrlen += buflen;

                continue;
            }

            /* ...otherwise we deal with stdout */
            if (overflow > 0) {

                const char **args;
                device_offset_t *offsets;
                const char *error;
                device_tokenize_state_t state = { 0 };

                int len = strlen(buf);
                char mandatory = buf[0];

                /* silently ignore lines that are too long */
                if (len && buf[len - 1] != '\n') {
                    skip = 1;
                    continue;
                }
                else if (skip) {
                    skip = 0;
                }
                /* ignore lines that do not start with '-' or '*' */
                else if (!('-' == mandatory || '*' == mandatory)) {
                    continue;
                }
                else if (APR_SUCCESS
                        != device_tokenize_to_argv(val, &args, &offsets,
                                NULL, &state, &error, dp->pool)) {
                    /* could not parse line, skip */
                    continue;
                }
                else if (state.escaped) {
                    /* half way through an escaped state, skip */
                    continue;
                }
                else if (state.isquoted) {
                    /* quotes are unclosed, skip */
                    continue;
                }
                else if (!args[0] || args[1] || !offsets) {
                    /* one argument and one argument only, otherwise skip */
                    continue;
                }
                else {


                    len--;

                    if (dp->p.key) {
                        if (offsets->equals > -1) {

                            apr_size_t size = strlen(dp->p.key);

                            if (!strncmp(args[0], dp->p.key, size)) {

                                if (mandatory == '*') {
                                    dp->p.required = 1;
                                }

                                result = apr_array_push(dp->p.values);

                                result->size = len - (offsets->equals) - 2;
                                result->name = apr_pstrndup(dp->pool, args[0] + offsets->equals + 1, result->size);

                                if (size <= (offsets->equals)) {
                                    dp->p.key = apr_pstrndup(dp->pool, args[0], offsets->equals);
                                }

                            }
                            else {
                                /* key doesn't match, ignore */
                                continue;
                            }
                        }
                        else {
                            /* ignore - no equals */
                            continue;
                        }
                    }
                    else {
                        if (offsets->equals > -1) {
                            if (mandatory == '*') {
                                result = apr_array_push(dp->p.requires);
                            }
                            else {
                                result = apr_array_push(dp->p.keys);
                            }

                            result->size = offsets->equals;
                            result->name = apr_pstrndup(dp->pool, args[0], result->size);
                        }
                        else {
                            result = apr_array_push(dp->p.values);

                            result->size = len - 1;
                            result->name = apr_pstrndup(dp->pool, args[0], result->size);
                        }
                    }

                    count++;
                }

            }
            else {
                /* no more, bail out */
                dp->p.error = apr_psprintf(dp->pool,
                        "more than %d parameters read, not completing.\n",
                        DEVICE_MAX_PARAMETERS);
                break;
            }

            overflow--;
        }
        else if (APR_EOF == status) {
            break;
        }
        else {
            dp->p.error = apr_psprintf(dp->pool, "cannot read from command: %pm\n", &status);
            break;
        }

    }

    if (dp->p.stderr) {
        apr_pool_cleanup_register(dp->pool, dp->p.stderr, cleanup_realloc,
                apr_pool_cleanup_null);
    }

    // apr_file_close(proc->out);

    if ((status = apr_proc_wait(proc, &exitcode, &exitwhy, APR_WAIT)) != APR_CHILD_DONE) {
        dp->p.error = apr_psprintf(dp->pool, "cannot wait for command: %pm\n", &status);
        return dp;
    }

    if (exitcode != 0 || exitwhy != APR_PROC_EXIT) {
        dp->p.error = apr_psprintf(dp->pool, "command exited %s with code %d\n",
                exitwhy == APR_PROC_EXIT ? "normally" :
                        exitwhy == APR_PROC_SIGNAL ? "on signal" :
                                exitwhy == APR_PROC_SIGNAL_CORE ? "and dumped core" :
                                        "", exitcode);
        return dp;
    }

    return dp;
}

device_parse_t *device_builtin_make(device_parse_t *dp, const char *name)
{
    dp->name = apr_pstrdup(dp->pool, name);
    dp->type = DEVICE_PARSE_BUILTIN;

    return dp;
}

device_parse_t *device_option_make(device_parse_t *dp,
        const char *name, device_parse_t *command)
{
    dp->name = apr_pstrdup(dp->pool, name);
    dp->type = DEVICE_PARSE_OPTION;
    dp->o.command = command;

    return dp;
}

apr_status_t device_parse(device_t *d, const char *arg, device_offset_t *offset,
        device_parse_t *parent, int completion, device_parse_t **result)
{
    const device_name_t *name;
    device_parse_t *current;

    int matches;

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

        /* handle parent match */
        if (!strcmp(arg, "..")) {
            if (parent->parent) {
                *result = current = parent->parent;
            }
            else {
                return APR_EABOVEROOT;
            }
        }

        /* handle exact matches */
        else if ((name = device_find_name(parent->c.builtins, arg))) {
            *result = current = device_builtin_make(device_parse_make(parent->pool, parent),
                    name->name);
        }
        else if ((name = device_find_name(parent->c.commands, arg))) {
            *result = current = device_command_make(device_parse_make(parent->pool, parent),
                    parent->c.libexec, parent->c.sysconf, name->name, d->pathext);
        }
        else if ((name = device_find_name(parent->c.containers, arg))) {
            *result = current = device_container_make(device_parse_make(parent->pool, parent),
                    parent->c.libexec, parent->c.sysconf, name->name, d->pathext);
        }

        /* handle prefix matches with exactly one result */
        else if (1 == (matches = device_find_prefix(parent->c.builtins, arg, &bname) +
                   device_find_prefix(parent->c.commands, arg, &rname) +
                   device_find_prefix(parent->c.containers, arg, &cname))) {

            if (bname) {
                *result = current = device_builtin_make(device_parse_make(parent->pool, parent),
                        bname->name);
            }
            else if (rname) {
                *result = current = device_command_make(device_parse_make(parent->pool, parent),
                        parent->c.libexec, parent->c.sysconf, rname->name, d->pathext);
            }
            else if (cname) {
                *result = current = device_container_make(device_parse_make(parent->pool, parent),
                        parent->c.libexec, parent->c.sysconf, cname->name, d->pathext);
            }
            else {
                /* theoretically not possible */
                return APR_EGENERAL;
            }

        }

        /* handle ambiguous results */
        else if (1 < matches) {

            char *common = NULL;

            *result = current = device_ambiguous_make(device_parse_make(parent->pool, parent), arg);

            device_find_prefixes(parent->c.builtins, arg, current->a.builtins, &common);
            device_find_prefixes(parent->c.commands, arg, current->a.commands, &common);
            device_find_prefixes(parent->c.containers, arg, current->a.containers, &common);

            current->a.prefix = apr_pstrdup(current->pool, arg);
            current->a.common = common;
        }

        /* handle no results */
        else {
            return APR_ENOENT;
        }

        break;
    }
    case DEVICE_PARSE_COMMAND: {

        const char **env = device_environment_make(d);

        *result = current = device_parameter_make(device_parse_make(parent->pool, parent), arg,
                offset, parent, env, completion);

        break;
    }
    case DEVICE_PARSE_PARAMETER: {

        const char **env = device_environment_make(d);

        *result = current = device_parameter_make(device_parse_make(parent->pool, parent), arg,
                offset, parent->p.command, env, completion);

        break;
    }
    case DEVICE_PARSE_BUILTIN: {

        *result = current = device_builtin_make(device_parse_make(parent->pool, parent), arg);

        break;
    }
    case DEVICE_PARSE_OPTION: {

        *result = current = device_option_make(device_parse_make(parent->pool, parent), arg,
                parent->o.command);

        break;
    }
    case DEVICE_PARSE_AMBIGUOUS: {

        /* by definition, nothing can be found under an ambiguous parent */
        return APR_ENOENT;
    }
    default: {
        return APR_EINVAL;
    }
    }

    /* did we successfully parse the command? */

    if (offset) {
        (*result)->offset = offset;
    }

    /* until further notice */
    current->completion = " ";

    /* we parsed a parameter */
    if (current->type == DEVICE_PARSE_PARAMETER) {

        const device_name_t *kname = NULL;
        const device_name_t *rname = NULL;
        const device_name_t *vname = NULL;

        if (current->p.key) {

            /* handle exact matches */
            if ((device_find_name(current->p.values, current->p.value))) {
                /* exact matches are fine */
            }

            /* handle prefix matches with exactly one result */
            else if (1 == (matches = device_find_prefix(current->p.values, current->p.value, &vname))) {

                if (vname) {
                    current->p.value = vname->name;
                    current->name = apr_pstrcat(current->pool, current->p.key, "=", vname->name, NULL);
                }

            }

            /* handle ambiguous results */
            else if (1 < matches) {

                char *common = NULL;
                const char *value = current->p.value;
                apr_array_header_t *values = current->p.values;

                device_ambiguous_make(current, arg);

                device_find_prefixes(values, value, current->a.values, &common);

                current->a.prefix = apr_pstrdup(current->pool, arg);
                current->a.common = common;
            }

        }

        else if (current->p.value) {

            /* handle exact matches */
            if ((device_find_name(current->p.requires, arg))) {
                /* exact matches are fine */
                current->p.required = 1;
            }
            else if ((device_find_name(current->p.keys, arg))) {
                /* exact matches are fine */
            }
            else if ((device_find_name(current->p.values, arg))) {
                /* exact matches are fine */
            }

            /* handle prefix matches with exactly one result */
            else if (1 == (matches = device_find_prefix(current->p.keys, arg, &kname) +
                             device_find_prefix(current->p.requires, arg, &rname) +
                           device_find_prefix(current->p.values, arg, &vname))) {

                if (kname) {
                    current->p.key = kname->name;
                    current->p.value = "";
                    current->name = apr_pstrcat(current->pool, current->p.key, NULL);

                    current->completion = "=";

                }
                else if (rname) {
                    current->p.required = 1;
                    current->p.key = rname->name;
                    current->p.value = "";
                    current->name = apr_pstrcat(current->pool, current->p.key, NULL);

                    current->completion = "=";

                }
                else if (vname) {
                    current->p.value = vname->name;
                    current->name = vname->name;
                }

            }

            /* handle ambiguous results */
            else if (1 < matches) {

                char *common = NULL;
                const char *value = current->p.value;
                apr_array_header_t *keys = current->p.keys;
                apr_array_header_t *requires = current->p.requires;
                apr_array_header_t *values = current->p.values;

                device_ambiguous_make(current, arg);

                device_find_prefixes(keys, value, current->a.keys, &common);
                device_find_prefixes(requires, value, current->a.requires, &common);
                device_find_prefixes(values, value, current->a.values, &common);

                current->a.prefix = apr_pstrdup(current->pool, arg);
                current->a.common = common;
            }

        }

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
    first = current = device_container_make(device_parse_make(d->pool, NULL), d->libexec,
            d->sysconf, NULL, d->pathext);

    /* walk the saved path */
    for (i = 0; !root && d->args && i < d->args->nelts; i++)
    {
        const char *arg = APR_ARRAY_IDX(d->args, i, const char *);

        if (APR_SUCCESS != (status = device_parse(d, arg, NULL, current, 0, &current))) {

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
                device_parse(d, arg, offsets, current, 1, &current))) {

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
    first = current = device_container_make(device_parse_make(d->pool, NULL), d->libexec,
            d->sysconf, NULL, d->pathext);

    /* walk the saved path */
    for (i = 0; !root && d->args && i < d->args->nelts; i++)
    {
        const char *arg = APR_ARRAY_IDX(d->args, i, const char *);

        if (APR_SUCCESS != (status = device_parse(d, arg, NULL, current, 1, &current))) {

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
                device_parse(d, arg, offsets, current, 1, &current))) {

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
        device_offset_t offset = { NULL, 0, 0, -1, 0 };

        if (APR_SUCCESS != (status = device_parse(d, "", &offset, current, 1, &current))) {

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
    apr_status_t status = APR_SUCCESS;

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
    first = current = device_container_make(device_parse_make(d->pool, NULL), d->libexec,
            d->sysconf, NULL, d->pathext);

    /* walk the saved path */
    for (i = 0; !root && d->args && i < d->args->nelts; i++)
    {
        const char *arg = APR_ARRAY_IDX(d->args, i, const char *);

        if (APR_SUCCESS
                != (status = device_parse(d, arg, NULL, current, 0, &current))) {

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
                device_parse(d, arg, offsets, current, 0, &current))) {

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
        const char *error = NULL;
        apr_finfo_t finfo;
        int count = 0;
        int i;
        int exitcode = 0;
        apr_exit_why_e exitwhy = 0;

        /* go back and find the command */
        command = current;
        while (command->type == DEVICE_PARSE_PARAMETER) {
            if ((error = command->p.error)) {
                break;
            }
            count++;
            command = command->parent;
        }
        if (error) {
            apr_file_printf(d->err, "%s", error);
            break;
        }

        /* go forward, create the arguments */
        argv = apr_array_make(first->pool, count * 2 + 3, sizeof(const char *));

        arg = apr_array_push(argv);
        *arg = command->r.libexec;

        arg = apr_array_push(argv);
        *arg = "--";

        for (i = 0; i < count; i++) {
            apr_array_push(argv);
            apr_array_push(argv);
        }
        apr_array_push(argv);

        while (count) {

            count--;

            (APR_ARRAY_IDX(argv, (count * 2 + 2), const char *)) =
                    current->p.key ? current->p.key :
                            current->p.value ? current->p.value : "";

            (APR_ARRAY_IDX(argv, (count * 2 + 3), const char *)) =
                    current->p.key && current->p.value ? current->p.value : "";

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
            apr_file_printf(d->err, "cannot set stderr: %pm\n", &status);
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

        if ((status = apr_proc_wait(proc, &exitcode, &exitwhy, APR_WAIT)) != APR_CHILD_DONE) {
            apr_file_printf(d->err, "cannot wait for command: %pm\n", &status);
            break;
        }

        if (exitcode != 0 || exitwhy != APR_PROC_EXIT) {
            if (exitwhy != APR_PROC_EXIT) {
                apr_file_printf(d->err, "command exited %s with code %d\n",
                        exitwhy == APR_PROC_EXIT ? "normally" :
                        exitwhy == APR_PROC_SIGNAL ? "on signal" :
                        exitwhy == APR_PROC_SIGNAL_CORE ? "and dumped core" : "",
                        exitcode);
            }
            status = APR_EGENERAL;
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

            status = APR_EOF;
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

        status = APR_ENOENT;
    }
    }

    apr_pool_destroy(first->pool);

    return status;
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

#if HAVE_LIBGEN_H
    d.base = basename(apr_pstrdup(d.pool, argv[0]));
#else
    d.base = DEFAULT_BASE;
#endif

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
        if (0) {
            /* do nothing */
        }
#ifdef HAVE_HISTEDIT_H
        else if (!strcmp(editline, DEVICE_LIBEDIT)) {
            lines = DEVICE_PREFER_LIBEDIT;
        }
#endif
#ifdef HAVE_EDITLINE_H
        else if (!strcmp(editline, DEVICE_EDITLINE)) {
            lines = DEVICE_PREFER_EDITLINE;
        }
#endif
#ifdef HAVE_REPLXX_H
        else if (!strcmp(editline, DEVICE_REPLXX)) {
            lines = DEVICE_PREFER_REPLXX;
        }
#endif
#ifdef HAVE_LINENOISE_H
        else if (!strcmp(editline, DEVICE_LINENOISE)) {
            lines = DEVICE_PREFER_LINENOISE;
        }
#endif
        else {
            apr_file_printf(d.err,
                    "DEVICE_EDITLINE value '%s' is not supported. Must be one of:"
#ifdef HAVE_HISTEDIT_H
                    " " DEVICE_LIBEDIT
#endif
#ifdef HAVE_EDITLINE_H
                    " " DEVICE_EDITLINE
#endif
#ifdef HAVE_REPLXX_H
                    " " DEVICE_REPLXX
#endif
#ifdef HAVE_LINENOISE_H
                    " " DEVICE_LINENOISE
#endif
                    "\n", editline);
            apr_pool_destroy(d.pool);
            exit(1);
        }
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
