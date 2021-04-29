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
 * Use editline for command line handling.
 */

#include "device_editline.h"

#include "config.h"
#include "device.h"

#ifdef HAVE_EDITLINE_H

#include <stdlib.h>
#include <editline.h>

#include <apr_escape.h>
#include <apr_strings.h>
#include <apr_hash.h>

/* global variable hack to get completion to work */
static device_t *device = NULL;

static char *device_prompt(device_t *d)
{
    return apr_psprintf(d->tpool, "(%s) %s@%s /%s> ", d->base, d->user, d->hostname,
            d->args ? apr_array_pstrcat(d->tpool, d->args, ' ') : "");
}

static char *
device_completion_hook(char *token, int *match)
{
    device_t *d = device;
    apr_pool_t *pool = NULL;
    const char **args;
    device_offset_t *offsets;
    device_tokenize_state_t *states;
    device_tokenize_state_t state = { 0 };
    const char *error;
    char *res = NULL;

    device_parse_t *current;
    apr_status_t status;

    device_save_termios();

    if (APR_SUCCESS != device_tokenize_to_argv(apr_pstrndup(d->tpool, rl_line_buffer, rl_point),
            &args, &offsets, &states, &state, &error, d->tpool)) {

        /* do nothing */

    }

    else if (APR_SUCCESS == (status = device_complete(d, args, offsets, state, &current, &pool))) {

        if (current->type == DEVICE_PARSE_AMBIGUOUS) {

            /* any common text? */
            if (current->a.common) {

                /* common */
                *match = 1;

                /* return a string that can be free()'d */
                res = strdup(current->a.common);

            }
            else {

                /* ambiguous, sorry */
                *match = 0;

            }

        }
        else if (current->type == DEVICE_PARSE_PARAMETER) {

            if (current->p.key && current->offset->equals > -1) {
                if (current->p.value[0]) {

                    /* unique */
                    *match = 1;

                    /* return a string that can be free()'d */
                    const char *n = current->p.value;
                    if (strlen(token) <= strlen(n)) {
                        res = strdup(apr_pstrcat(pool, n + strlen(token), current->completion, NULL));
                    }

                }
                else {
                    /* key but empty value, print nothing */
                }
            }
            else {

                /* unique */
                *match = 1;

                /* return a string that can be free()'d */
                const char *n = current->name;
                if (strlen(token) <= strlen(n)) {
                    res = strdup(apr_pstrcat(pool, n + strlen(token), current->completion, NULL));
                }

            }

        }
        else {

            /* unique */
            *match = 1;

            /* return a string that can be free()'d */
//            const char *n = device_pescape_shell(pool, current->name);
            const char *n = current->name;
            if (strlen(token) <= strlen(n)) {
                res = strdup(apr_pstrcat(pool, n + strlen(token), current->completion, NULL));
            }

        }

    }

    if (pool) {
        apr_pool_destroy(pool);
    }

    device_restore_termios();

    return res;
}

static int
device_list_possible_hook(char *token, char ***av)
{
    device_t *d = device;
    char **a;
    apr_pool_t *pool = NULL;
    const char **args;
    device_offset_t *offsets;
    device_tokenize_state_t *states;
    device_tokenize_state_t state = { 0 };
    const char *error;

    device_parse_t *current;
    apr_status_t status;
    int i, j = 0;
    int count = 0;

    device_save_termios();

    if (APR_SUCCESS != device_tokenize_to_argv(apr_pstrndup(d->tpool, rl_line_buffer, rl_point),
            &args, &offsets, &states, &state, &error, d->tpool)) {

        /* do nothing */

    }

    else if (APR_SUCCESS == (status = device_complete(d, args, offsets, state, &current, &pool))) {

        if (current->type == DEVICE_PARSE_AMBIGUOUS) {

            count = current->a.containers->nelts + current->a.commands->nelts + current->a.builtins->nelts +
                    current->a.keys->nelts + current->a.requires->nelts + current->a.values->nelts;

            *av = a = malloc(count * sizeof(char *));

            for (i = 0; i < current->a.containers->nelts; i++)
            {
                const device_name_t *name = &APR_ARRAY_IDX(current->a.containers, i, const device_name_t);

                /* return a string that can be free()'d */
                a[j++] = strdup(device_pescape_shell(pool, name->name));

            }

            for (i = 0; i < current->a.commands->nelts; i++)
            {
                const device_name_t *name = &APR_ARRAY_IDX(current->a.commands, i, const device_name_t);

                /* return a string that can be free()'d */
                a[j++] = strdup(device_pescape_shell(pool, name->name));

            }

            for (i = 0; i < current->a.builtins->nelts; i++)
            {
                const device_name_t *name = &APR_ARRAY_IDX(current->a.builtins, i, const device_name_t);

                /* return a string that can be free()'d */
                a[j++] = strdup(device_pescape_shell(pool, name->name));

            }

            for (i = 0; i < current->a.keys->nelts; i++)
            {
                const device_name_t *name = &APR_ARRAY_IDX(current->a.keys, i, const device_name_t);

                /* return a string that can be free()'d */
                a[j++] = strdup(device_pescape_shell(pool, name->name));

            }

            for (i = 0; i < current->a.requires->nelts; i++)
            {
                const device_name_t *name = &APR_ARRAY_IDX(current->a.requires, i, const device_name_t);

                /* return a string that can be free()'d */
                a[j++] = strdup(device_pescape_shell(pool, name->name));

            }

            for (i = 0; i < current->a.values->nelts; i++)
            {
                const device_name_t *name = &APR_ARRAY_IDX(current->a.values, i, const device_name_t);

                /* return a string that can be free()'d */
                a[j++] = strdup(device_pescape_shell(pool, name->name));

            }

        }
        else if (current->type == DEVICE_PARSE_PARAMETER) {

            if (current->p.key && current->offset->equals > -1) {
                if (current->p.value[0]) {

                    count = 1;

                    *av = a = malloc(sizeof(char *));

                    /* return a string that can be free()'d */
                    *a = strdup(apr_pstrcat(pool, device_pescape_shell(pool,
                            current->p.value), current->completion, NULL));

                }
                else {
                    /* key but empty value, print nothing */
                }
            }
            else {

                count = 1;

                *av = a = malloc(sizeof(char *));

                /* return a string that can be free()'d */
                *a = strdup(apr_pstrcat(pool, device_pescape_shell(pool, current->name), "", NULL));

            }

        }
        else {

            count = 1;

            *av = a = malloc(sizeof(char *));

            /* return a string that can be free()'d */
            *a = strdup(apr_pstrcat(pool, device_pescape_shell(pool, current->name), "", NULL));

        }

    }

    if (pool) {
        apr_pool_destroy(pool);
    }

    apr_pool_clear(d->tpool);

    device_restore_termios();

    return count;
}

int device_editline(device_t *d, const char *name)
{
    apr_size_t lines = 0;

    apr_hash_t *prompts = apr_hash_make(d->pool);

    const char *home = getenv("HOME");

    device = d;

    rl_initialize();

    rl_set_complete_func(&device_completion_hook);
    rl_set_list_possib_func(&device_list_possible_hook);

    if (home) {
        if (APR_SUCCESS == apr_filepath_set(home, d->pool)) {
            read_history(DEVICE_HISTORY);
        }
    }

    while (1) {
        char *result = NULL;
        const char **args;
        device_offset_t *offsets;
        device_tokenize_state_t *states;
        device_tokenize_state_t state = { 0 };
        const char *error;
        const char *prompt = device_prompt(d);
        const char *buf;

        /*
         * editline has a bug - it keeps an internal copy of the
         * last prompt, and breaks if we free it.
         *
         * We leak, but in a controlled way - we store every prompt
         * we've ever needed, and reuse them instead of freeing them.
         *
         * https://github.com/troglobit/editline/issues/51
         */
        buf = apr_hash_get(prompts, prompt, APR_HASH_KEY_STRING);
        if (!buf) {
            prompt = apr_pstrdup(d->pool, prompt);
            apr_hash_set(prompts, prompt, APR_HASH_KEY_STRING, prompt);
        }
        else {
            prompt = buf;
        }

        result = readline(prompt);

        rl_set_prompt(NULL);

        if (!result) {
            apr_file_printf(d->out, "\n");
            break;
        }

        if (APR_SUCCESS != device_tokenize_to_argv(result, &args, &offsets, &states, &state, &error, d->tpool)) {
            apr_file_printf(d->err, "syntax error at '%c' (line %" APR_SIZE_T_FMT
                    " column %ld)\n", *error, lines + 1, (error - result) + 1);
        }

        else if (args[0]) {
            if (APR_EOF == device_command(d, args, offsets, lines)) {
                apr_file_printf(d->out, "\n");
                free(result);
                break;
            }
        }

        lines++;

        free(result);
        apr_pool_clear(d->tpool);
    }

    if (home) {
        if (APR_SUCCESS == apr_filepath_set(home, d->pool)) {
            write_history(DEVICE_HISTORY);
        }
    }

    rl_uninitialize();

    return 0;
}

#endif
