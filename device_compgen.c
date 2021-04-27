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
 * Handle completions from the shell.
 */

#include "device_compgen.h"

#include <apr_lib.h>
#include <apr_strings.h>

#include "config.h"
#include "device.h"

int device_compgen(device_t *d, const char *context)
{
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

    else if (!args || !args++ || !offsets || !offsets++) {

        /* do nothing */

    }

    else if (APR_SUCCESS == (status = device_complete(d, args, offsets, state, &current, &pool))) {

        if (current->type == DEVICE_PARSE_AMBIGUOUS) {

            for (i = 0; i < current->a.containers->nelts; i++)
            {
                const device_name_t *name = &APR_ARRAY_IDX(current->a.containers, i, const device_name_t);

                apr_file_printf(d->out, "%s\n", apr_pstrcat(pool, name->name, " ", NULL));

            }

            for (i = 0; i < current->a.commands->nelts; i++)
            {
                const device_name_t *name = &APR_ARRAY_IDX(current->a.commands, i, const device_name_t);

                apr_file_printf(d->out, "%s\n", apr_pstrcat(pool, name->name, " ", NULL));

            }

            /* no builtins for command line */
#if 0
            for (i = 0; i < current->a.builtins->nelts; i++)
            {
                const device_name_t *name = &APR_ARRAY_IDX(current->a.builtins, i, const device_name_t);

                apr_file_printf(d->out, "%s\n", apr_pstrcat(pool, name->name, " ", NULL));

            }
#endif

            for (i = 0; i < current->a.keys->nelts; i++)
            {
                const device_name_t *name = &APR_ARRAY_IDX(current->a.keys, i, const device_name_t);

                apr_file_printf(d->out, "%s\n", apr_pstrcat(pool, name->name, "=", NULL));

            }

            for (i = 0; i < current->a.requires->nelts; i++)
            {
                const device_name_t *name = &APR_ARRAY_IDX(current->a.requires, i, const device_name_t);

                apr_file_printf(d->out, "%s\n", apr_pstrcat(pool, name->name, "=", NULL));

            }

            for (i = 0; i < current->a.values->nelts; i++)
            {
                const device_name_t *name = &APR_ARRAY_IDX(current->a.values, i, const device_name_t);

                apr_file_printf(d->out, "%s\n", apr_pstrcat(pool, name->name, " ", NULL));

            }

        }
        else if (current->type == DEVICE_PARSE_PARAMETER) {

            if (current->p.key && current->p.value && current->p.value[0]) {
                apr_file_printf(d->out, "%s\n", apr_pstrcat(pool, current->p.value, " ", NULL));
            }
            else {
                apr_file_printf(d->out, "%s\n", apr_pstrcat(pool, current->name, current->completion, NULL));
            }

        }
        else if (current->name) {

            apr_file_printf(d->out, "%s\n", apr_pstrcat(pool, current->name, current->completion, NULL));

        }

    }

    if (pool) {
        apr_pool_destroy(pool);
    }

    apr_pool_clear(d->tpool);

    return 0;
}
