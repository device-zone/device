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
 * Use replxx for command line handling.
 */

#include "device_replxx.h"

#include "config.h"
#include "device.h"

#ifdef HAVE_REPLXX_H

#include <stdlib.h>
#include <replxx.h>

#include <apr_escape.h>
#include <apr_strings.h>

static apr_status_t cleanup_replxx(void *dummy)
{
    replxx_end(dummy);

    return APR_SUCCESS;
}

static int utf8str_codepoint_len(char const* s, int utf8len)
{
    int codepointLen = 0;
    unsigned char m4 = 128 + 64 + 32 + 16;
    unsigned char m3 = 128 + 64 + 32;
    unsigned char m2 = 128 + 64;
    for (int i = 0; i < utf8len; ++ i, ++ codepointLen) {
        char c = s[i];
        if ( ( c & m4 ) == m4 ) {
            i += 3;
        } else if ( ( c & m3 ) == m3 ) {
            i += 2;
        } else if ( ( c & m2 ) == m2 ) {
            i += 1;
        }
    }
    return (codepointLen);
}

static void device_completion_hook(char const *context, replxx_completions *lc,
        int *contextLen, void *ud)
{
    device_t *d = ud;
    apr_pool_t *pool = NULL;
    const char **args;
    const char *error;
    device_offset_t *offsets;
    device_tokenize_state_t *states;
    device_tokenize_state_t state = { 0 };
    device_parse_t *current;
    apr_status_t status;
    int i;

    if (APR_SUCCESS
            != device_tokenize_to_argv(context, &args, &offsets, &states,
                    &state, &error, d->tpool)) {

        /* do nothing */

    }

    else if (APR_SUCCESS
            == (status = device_complete(d, args, offsets, state, &current,
                    &pool))) {

        if (current->type == DEVICE_PARSE_AMBIGUOUS) {

            for (i = 0; i < current->a.containers->nelts; i++)
            {
                const device_name_t
                    *name = &APR_ARRAY_IDX(current->a.containers, i, const device_name_t);

//                replxx_add_completion(lc, apr_pstrcat(pool, name->name, " ", NULL));
                replxx_add_color_completion(lc,
                        apr_pstrcat(pool,
                                device_pescape_shell(pool, name->name), " ",
                                NULL), REPLXX_COLOR_BLUE);

            }

            for (i = 0; i < current->a.commands->nelts; i++)
            {
                const device_name_t
                    *name = &APR_ARRAY_IDX(current->a.commands, i, const device_name_t);

//                replxx_add_completion(lc, apr_pstrcat(pool, name->name, " ", NULL));
                replxx_add_color_completion(lc,
                        apr_pstrcat(pool,
                                device_pescape_shell(pool, name->name), " ",
                                NULL), REPLXX_COLOR_BRIGHTBLUE);

            }

            for (i = 0; i < current->a.builtins->nelts; i++)
            {
                const device_name_t
                    *name = &APR_ARRAY_IDX(current->a.builtins, i, const device_name_t);

//                replxx_add_completion(lc, apr_pstrcat(pool, name->name, " ", NULL));
                replxx_add_color_completion(lc,
                        apr_pstrcat(pool,
                                device_pescape_shell(pool, name->name), " ",
                                NULL), REPLXX_COLOR_CYAN);

            }

            for (i = 0; i < current->a.keys->nelts; i++)
            {
                const device_name_t
                    *name = &APR_ARRAY_IDX(current->a.keys, i, const device_name_t);

//                replxx_add_completion(lc, apr_pstrcat(pool, name->name, "=", NULL));
                replxx_add_color_completion(lc,
                        apr_pstrcat(pool,
                                device_pescape_shell(pool, name->name), "=",
                                NULL), REPLXX_COLOR_MAGENTA);

            }

            for (i = 0; i < current->a.requires->nelts; i++)
            {
                const device_name_t
                    *name = &APR_ARRAY_IDX(current->a.requires, i, const device_name_t);

//                replxx_add_completion(lc, apr_pstrcat(pool, name->name, "=", NULL));
                replxx_add_color_completion(lc,
                        apr_pstrcat(pool,
                                device_pescape_shell(pool, name->name), "=",
                                NULL), REPLXX_COLOR_BRIGHTMAGENTA);

            }

            for (i = 0; i < current->a.values->nelts; i++)
            {
                const device_name_t
                    *name = &APR_ARRAY_IDX(current->a.values, i, const device_name_t);

//                replxx_add_completion(lc, apr_pstrcat(pool, name->name, " ", NULL));
                replxx_add_color_completion(lc,
                        apr_pstrcat(pool,
                                device_pescape_shell(pool, name->name), " ",
                                NULL), REPLXX_COLOR_MAGENTA);

            }

        }
        else if (current->type == DEVICE_PARSE_PARAMETER) {

            if (current->p.key && current->offset->equals > -1) {
                if (current->p.value[0]) {
                    replxx_add_completion(lc,
                            apr_pstrcat(pool, device_pescape_shell(pool, current->p.value),
                                    current->completion, NULL));
                }
                else {
                    /* key but empty value, print nothing */
                }
            }
            else {
                replxx_add_completion(lc,
                        apr_pstrcat(pool, device_pescape_shell(pool, current->name),
                                current->completion, NULL));
            }

        }
        else {

            replxx_add_completion(lc,
                    apr_pstrcat(pool, device_pescape_shell(pool, current->name),
                            current->completion, NULL));

        }

    }

    if (pool) {
        apr_pool_destroy(pool);
    }

    apr_pool_clear(d->tpool);

}

static void device_colour_hook(char const *context, ReplxxColor *colours, int size, void *ud)
{
    device_t *d = ud;
    apr_pool_t *pool = NULL;
    const char **args;
    const char *buffer;
    const char *error;
    device_offset_t *offsets;
    const unsigned int *offset;
    device_tokenize_state_t *states;
    device_tokenize_state_t state = { 0 };
    device_parse_t *current;
    apr_status_t status;
    int i;

    if (APR_SUCCESS != device_tokenize_to_argv(context, &args, &offsets, &states, &state, &error, d->tpool)) {

        /* colourise the error */
        for (buffer = context, i = 0; *buffer && i < size; buffer += utf8str_codepoint_len(buffer, 1), i++) {
            if (context == error) {
                colours[i] = REPLXX_COLOR_ERROR;
            }
        }

    }

    else if (APR_SUCCESS == (status = device_colourise(d, args, offsets, state, &current, &pool))) {

        if (current) {

            for (buffer = context, i = 0; *buffer && i < size; buffer += utf8str_codepoint_len(buffer, 1), i++) {

                if ((states+(buffer-context))->escaped != DEVICE_TOKEN_NOESCAPE) {
                    colours[i] = REPLXX_COLOR_BRIGHTMAGENTA;
                }
                else if ((states+(buffer-context))->isquoted != DEVICE_TOKEN_NOQUOTE) {
                    colours[i] = REPLXX_COLOR_GRAY;
                }

            }

            while (current) {

                if (current->name && current->offset && current->offset->offsets) {

                    for (buffer = current->name, offset = current->offset->offsets;
                            buffer && (offset - current->offset->offsets < current->offset->size - 1);
                            offset += utf8str_codepoint_len(buffer, 1), buffer += utf8str_codepoint_len(buffer, 1)) {

                        switch (current->type) {
                        case DEVICE_PARSE_CONTAINER:
                            colours[utf8str_codepoint_len(context, *offset)] = REPLXX_COLOR_BLUE;
                            break;
                        case DEVICE_PARSE_COMMAND:
                            colours[utf8str_codepoint_len(context, *offset)] = REPLXX_COLOR_BRIGHTBLUE;
                            break;
                        case DEVICE_PARSE_BUILTIN:
                            colours[utf8str_codepoint_len(context, *offset)] = REPLXX_COLOR_CYAN;
                            break;
                        case DEVICE_PARSE_PARAMETER:
                            if (current->p.error) {
                                colours[utf8str_codepoint_len(context, *offset)] = REPLXX_COLOR_BRIGHTRED;
                            }
                            else if (current->p.required) {
                                colours[utf8str_codepoint_len(context, *offset)] = REPLXX_COLOR_BRIGHTGREEN;
                            }
                            else {
                                colours[utf8str_codepoint_len(context, *offset)] = REPLXX_COLOR_GREEN;
                            }
                            break;
                        default:
                            break;
                        }

                    }

                }

                current = current->parent;
            }

        }
        else {

            for (i = 0 ; i < size; ++ i) {
                colours[utf8str_codepoint_len(context, i)] = REPLXX_COLOR_LIGHTGRAY;
            }

        }

    }

    if (pool) {
        apr_pool_destroy(pool);
    }

    apr_pool_clear(d->tpool);

}

static const char *device_prompt(device_t *d)
{
    return apr_psprintf(d->tpool, "\x1b[1;37m(device)\x1b[0m \x1b[1;32m%s@%s\x1b[0m /%s> ",
            d->user, d->hostname, d->args ? apr_array_pstrcat(d->tpool, d->args, ' ') : "");
}

int device_replxx(device_t *d)
{
    apr_size_t lines = 0;

    const char *home = getenv("HOME");

    Replxx* replxx = replxx_init();

    apr_pool_cleanup_register(d->pool, replxx, cleanup_replxx, cleanup_replxx);

    replxx_install_window_change_handler(replxx);
    replxx_set_unique_history(replxx, 1);
    replxx_set_word_break_characters(replxx, " \t\"'");
    replxx_set_completion_callback(replxx, device_completion_hook, d);
    replxx_set_highlighter_callback(replxx, device_colour_hook, d);

    if (home) {
        if (APR_SUCCESS == apr_filepath_set(home, d->pool)) {
            replxx_history_load(replxx, DEVICE_HISTORY);
        }
    }

    while (1) {
        const char *result = NULL;
        const char **args;
        device_offset_t *offsets;
        device_tokenize_state_t *states;
        device_tokenize_state_t state = { 0 };
        const char *error;

        do {
            result = replxx_input(replxx, device_prompt(d));
        } while ( ( result == NULL ) && ( errno == EAGAIN ) );

        if (result == NULL) {
            printf("\n");
            break;
        }

        if (APR_SUCCESS != device_tokenize_to_argv(result, &args, &offsets, &states, &state, &error, d->tpool)) {
            apr_file_printf(d->err, "syntax error at '%c' (line %" APR_SIZE_T_FMT
                    " column %ld)\n", *error, lines + 1, (error - result) + 1);
        }

        else if (args[0]) {
            replxx_history_add(replxx, result);

            if (APR_EOF == device_command(d, args, offsets, lines)) {
                printf("\n");
                break;
            }

        }

        lines++;

        apr_pool_clear(d->tpool);
    }

    if (home) {
        replxx_history_save(replxx, DEVICE_HISTORY);
    }

    return 0;
}


#endif
