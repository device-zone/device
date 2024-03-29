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
 * Use linenoise for command line handling.
 */

#include "device_linenoise.h"

#include "config.h"
#include "device.h"

#ifdef HAVE_LINENOISE_H

#include "linenoise.h"

#include <apr_escape.h>
#include <apr_strings.h>

#include <stdlib.h>

/* global variable hack to get completion to work */
static device_t *device = NULL;

static void device_completion_hook(char const *context, linenoiseCompletions *lc)
{
    device_t *d = device;
    apr_pool_t *pool = NULL;
    const char **args;
    const char *error;
    device_offset_t *offsets;
    device_tokenize_state_t *states;
    device_tokenize_state_t state = { 0 };
    device_parse_t *current;
    apr_status_t status;
    int i;

    device_save_termios();

    if (APR_SUCCESS != device_tokenize_to_argv(context, &args, &offsets, &states, &state, &error, d->tpool)) {

        /* do nothing */

    }

    else if (APR_SUCCESS == (status = device_complete(d, args, offsets, state, &current, &pool))) {

        const char *prefix;

        if (current->offset->offsets) {
            prefix = apr_pstrndup(pool, context, current->offset->start);
        }
        else {
            prefix = context;
        }

        if (current->type == DEVICE_PARSE_AMBIGUOUS) {

            for (i = 0; i < current->a.containers->nelts; i++)
            {
                const device_name_t *name = &APR_ARRAY_IDX(current->a.containers, i, const device_name_t);

                linenoiseAddCompletion(lc, apr_pstrcat(pool, prefix, device_pescape_shell(pool, name->name), NULL, " ", NULL));

            }

            for (i = 0; i < current->a.commands->nelts; i++)
            {
                const device_name_t *name = &APR_ARRAY_IDX(current->a.commands, i, const device_name_t);

                linenoiseAddCompletion(lc, apr_pstrcat(pool, prefix, device_pescape_shell(pool, name->name), NULL, " ", NULL));

            }

            for (i = 0; i < current->a.builtins->nelts; i++)
            {
                const device_name_t *name = &APR_ARRAY_IDX(current->a.builtins, i, const device_name_t);

                linenoiseAddCompletion(lc, apr_pstrcat(pool, prefix, device_pescape_shell(pool, name->name), NULL, " ", NULL));

            }

            for (i = 0; i < current->a.keys->nelts; i++)
            {
                const device_name_t *name = &APR_ARRAY_IDX(current->a.keys, i, const device_name_t);

                linenoiseAddCompletion(lc, apr_pstrcat(pool, prefix, device_pescape_shell(pool, name->name), NULL, "=", NULL));

            }

            for (i = 0; i < current->a.requires->nelts; i++)
            {
                const device_name_t *name = &APR_ARRAY_IDX(current->a.requires, i, const device_name_t);

                linenoiseAddCompletion(lc, apr_pstrcat(pool, prefix, device_pescape_shell(pool, name->name), NULL, "=", NULL));

            }

            for (i = 0; i < current->a.values->nelts; i++)
            {
                const device_name_t *name = &APR_ARRAY_IDX(current->a.values, i, const device_name_t);

                linenoiseAddCompletion(lc, apr_pstrcat(pool, prefix, device_pescape_shell(pool, name->name), NULL, " ", NULL));

            }

        }
        else if (current->type == DEVICE_PARSE_PARAMETER) {

            if (current->p.error) {
                /* error, print nothing */
            }
            else if (current->p.key && current->offset->equals > -1) {
                if (current->p.value[0]) {
                    linenoiseAddCompletion(lc, apr_pstrcat(pool, prefix, device_pescape_shell(pool, current->p.value), NULL, current->completion, NULL));
                }
                else {
                    /* key but empty value, print nothing */
                }
            }
            else {
                linenoiseAddCompletion(lc, apr_pstrcat(pool, prefix, device_pescape_shell(pool, current->name), NULL, current->completion, NULL));
            }

        }
        else {

            linenoiseAddCompletion(lc, apr_pstrcat(pool, prefix, device_pescape_shell(pool, current->name), NULL, current->completion, NULL));

        }

    }

    if (pool) {
        apr_pool_destroy(pool);
    }

    device_restore_termios();
}

static const char *device_prompt(device_t *d)
{
    return apr_psprintf(d->tpool, "\x1b[1;37m(%s)\x1b[0m \x1b[1;32m%s@%s\x1b[0m /%s> ",
            d->base, d->user, d->hostname, d->args ?
                    apr_array_pstrcat(d->tpool, d->args, ' ') : "");
}

int device_linenoise(device_t *d)
{
    apr_size_t lines = 0;

    const char *home = getenv("HOME");

    device = d;

    linenoiseSetCompletionCallback(device_completion_hook);

    linenoiseSetMultiLine(1);
    if (home) {
        linenoiseHistorySetMaxLen(DEVICE_HISTORY_MAXLEN);
        if (APR_SUCCESS == apr_filepath_set(home, d->pool)) {
            linenoiseHistoryLoad(DEVICE_HISTORY);
        }
    }

    while (1) {
        char *result = NULL;
        const char **args;
        device_offset_t *offsets;
        device_tokenize_state_t *states;
        device_tokenize_state_t state = { 0 };
        const char *error;

        result = linenoise(device_prompt(d));

        if (result == NULL) {
            printf("\n");
            break;
        }

        if (APR_SUCCESS != device_tokenize_to_argv(result, &args, &offsets, &states, &state, &error, d->tpool)) {
            apr_file_printf(d->err, "syntax error at '%c' (line %" APR_SIZE_T_FMT
                    " column %ld)\n", *error, lines + 1, (error - result) + 1);
        }

        else if (args[0]) {
            if (home) {
                linenoiseHistoryAdd(result);
                linenoiseHistorySave(DEVICE_HISTORY);
            }

            if (APR_EOF == device_command(d, args, offsets, lines)) {
                printf("\n");
                free(result);
                break;
            }

        }

        lines++;

        free(result);
        apr_pool_clear(d->tpool);
    }

    return 0;
}

#endif
