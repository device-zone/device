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

#ifndef DEVICE_H
#define DEVICE_H

#include <apr_file_io.h>
#include <apr_pools.h>
#include <apr_tables.h>

#define DEVICE_HISTORY ".device_history"
#define DEVICE_HISTORY_MAXLEN 1000

#define DEVICE_MAX_PARAMETERS 1000

typedef struct device_name_t {
    apr_size_t size;
    const char *name;
} device_name_t;

typedef struct device_parse_t device_parse_t;

typedef enum device_type_e {
    DEVICE_PARSE_CONTAINER,
    DEVICE_PARSE_COMMAND,
    DEVICE_PARSE_PARAMETER,
    DEVICE_PARSE_BUILTIN,
    DEVICE_PARSE_OPTION,
    DEVICE_PARSE_AMBIGUOUS
} device_type_e;

typedef struct device_option_t {
    const char *value;
    device_parse_t *command;
} device_option_t;

typedef struct device_builtin_t {
    /* none needed */
} device_builtin_t;

typedef struct device_parameter_t {
    const char *key;
    const char *value;
    apr_array_header_t *keys;
    apr_array_header_t *requires;
    apr_array_header_t *values;
    device_parse_t *command;
    const char *error;
    int required;
} device_parameter_t;

typedef struct device_command_t {
    char *libexec;
    char *sysconf;
} device_command_t;

typedef struct device_container_t {
    char *libexec;
    char *sysconf;
    apr_array_header_t *containers;
    apr_array_header_t *commands;
    apr_array_header_t *builtins;
} device_container_t;

typedef struct device_ambiguous_t {
    const char *prefix;
    const char *common;
    apr_array_header_t *containers;
    apr_array_header_t *commands;
    apr_array_header_t *builtins;
    apr_array_header_t *keys;
    apr_array_header_t *requires;
    apr_array_header_t *values;
} device_ambiguous_t;

typedef struct device_offset_t {
    unsigned int *offsets;
    unsigned int start;
    unsigned int end;
    int equals;
    apr_size_t size;
} device_offset_t;

typedef struct device_parse_t {
    apr_pool_t *pool;
    const char *name;
    const char *completion;
    device_parse_t *parent;
    device_offset_t *offset;
    device_type_e type;
    union {
        device_container_t c;
        device_command_t r;
        device_parameter_t p;
        device_builtin_t b;
        device_option_t o;
        device_ambiguous_t a;
    };
} device_parse_t;

typedef struct device_t {
    apr_pool_t *pool;
    apr_pool_t *tpool;
    apr_file_t *err;
    apr_file_t *in;
    apr_file_t *out;
    const char *user;
    const char *hostname;
    const char *libexec;
    const char *sysconf;
    apr_array_header_t *pathext;
    apr_array_header_t *args;
} device_t;

typedef enum device_token_escape_e {
    DEVICE_TOKEN_NOESCAPE = 0,
    DEVICE_TOKEN_WASESCAPE,
    DEVICE_TOKEN_ESCAPE_SLASH,
    DEVICE_TOKEN_ESCAPE_OCTAL2,
    DEVICE_TOKEN_ESCAPE_OCTAL3,
    DEVICE_TOKEN_ESCAPE_HEX1,
    DEVICE_TOKEN_ESCAPE_HEX2,
    DEVICE_TOKEN_ESCAPE_UTF16_1,
    DEVICE_TOKEN_ESCAPE_UTF16_2,
    DEVICE_TOKEN_ESCAPE_UTF16_3,
    DEVICE_TOKEN_ESCAPE_UTF16_4,
    DEVICE_TOKEN_ESCAPE_UTF32_1,
    DEVICE_TOKEN_ESCAPE_UTF32_2,
    DEVICE_TOKEN_ESCAPE_UTF32_3,
    DEVICE_TOKEN_ESCAPE_UTF32_4,
    DEVICE_TOKEN_ESCAPE_UTF32_5,
    DEVICE_TOKEN_ESCAPE_UTF32_6,
    DEVICE_TOKEN_ESCAPE_UTF32_7,
    DEVICE_TOKEN_ESCAPE_UTF32_8,
    DEVICE_TOKEN_ESCAPE_CONTROL,
} device_token_escape_e;

typedef enum device_token_quoted_e {
    DEVICE_TOKEN_NOQUOTE = 0,
    DEVICE_TOKEN_WASQUOTE,
    DEVICE_TOKEN_SINGLEQUOTE,
    DEVICE_TOKEN_DOUBLEQUOTE,
} device_token_quoted_e;

typedef enum device_token_inside_e {
    DEVICE_TOKEN_OUTSIDE = 0,
    DEVICE_TOKEN_INSIDE,
} device_token_inside_e;

typedef enum device_token_equals_e {
    DEVICE_TOKEN_NOTSEEN = 0,
    DEVICE_TOKEN_SEEN,
} device_token_equals_e;

typedef struct device_tokenize_state_t {
    device_token_escape_e escaped:5;
    device_token_quoted_e isquoted:2;
    device_token_inside_e intoken:1;
    device_token_equals_e equals:1;
} device_tokenize_state_t;

apr_status_t device_tokenize_to_argv(const char *arg_str, const char ***argv_out,
        device_offset_t **argo_out, device_tokenize_state_t **states_out,
        device_tokenize_state_t *state, const char **err_out, apr_pool_t *pool);

const char *device_pescape_shell(apr_pool_t *p, const char *str);

void device_save_termios();

void device_restore_termios();

apr_status_t device_colourise(device_t *d, const char **args,
        device_offset_t *offsets, device_tokenize_state_t state,
        device_parse_t **result, apr_pool_t **pool);

apr_status_t device_complete(device_t *d, const char **args,
        device_offset_t *offsets, device_tokenize_state_t state,
        device_parse_t **result, apr_pool_t **pool);

apr_status_t device_command(device_t *d, const char **args,
        device_offset_t *offsets, apr_size_t line);

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 256
#endif

#endif
