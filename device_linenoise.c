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

    if (APR_SUCCESS != device_tokenize_to_argv(context, &args, &offsets, &states, &state, &error, d->tpool)) {

        /* do nothing */

    }

    else if (APR_SUCCESS == (status = device_complete(d, args, offsets, state, &current, &pool))) {

        if (current->type == DEVICE_PARSE_AMBIGUOUS) {

            for (i = 0; i < current->a.containers->nelts; i++)
            {
                const device_name_t *name = &APR_ARRAY_IDX(current->a.containers, i, const device_name_t);

//                replxx_add_color_completion(lc, name->name, REPLXX_COLOR_BRIGHTBLUE);
                linenoiseAddCompletion(lc, apr_pstrcat(pool, name->name, " ", NULL));

            }

            for (i = 0; i < current->a.commands->nelts; i++)
            {
                const device_name_t *name = &APR_ARRAY_IDX(current->a.commands, i, const device_name_t);

//                replxx_add_color_completion(lc, name->name, REPLXX_COLOR_BRIGHTBLUE);
                linenoiseAddCompletion(lc, apr_pstrcat(pool, name->name, " ", NULL));

            }

            for (i = 0; i < current->a.builtins->nelts; i++)
            {
                const device_name_t *name = &APR_ARRAY_IDX(current->a.builtins, i, const device_name_t);

//                replxx_add_color_completion(lc, name->name, REPLXX_COLOR_BRIGHTBLUE);
                linenoiseAddCompletion(lc, apr_pstrcat(pool, name->name, " ", NULL));

            }

        }
        else {

            linenoiseAddCompletion(lc, apr_pstrcat(pool, current->name, " ", NULL));

        }

    }

    if (pool) {
        apr_pool_destroy(pool);
    }

    apr_pool_clear(d->tpool);

//        char** examples = (char**)( ud );
//        size_t i;

//        int utf8ContextLen = context_len( context );
//        int prefixLen = (int)strlen( context ) - utf8ContextLen;
//        *contextLen = utf8str_codepoint_len( context + prefixLen, utf8ContextLen );
//        for (i = 0;     examples[i] != NULL; ++i) {
//                if (strncmp(context + prefixLen, examples[i], utf8ContextLen) == 0) {
//                        replxx_add_completion(lc, examples[i]);
//                }
//        }

//    replxx_add_completion(lc, "xfoo");
//    replxx_add_completion(lc, "xbar");

}

static const char *device_prompt(device_t *d)
{
    return apr_psprintf(d->tpool, "\x1b[1;37m(device)\x1b[0m \x1b[1;32m%s@%s\x1b[0m /%s> ",
            d->user, d->hostname, d->args ? apr_array_pstrcat(d->tpool, d->args, ' ') : "");
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
