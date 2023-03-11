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
 * Read commands from a file.
 */

#include "device_read.h"

#include <apr_lib.h>

#include "config.h"
#include "device.h"

int device_read(device_t *d)
{
    apr_size_t lines = 0;

    while (1) {
        char result[HUGE_STRING_LEN];
        const char **args;
        device_offset_t *offsets;
        device_tokenize_state_t *states;
        device_tokenize_state_t state = { 0 };
        const char *error;
        apr_status_t status;

        status = apr_file_gets(result, sizeof(result), d->in);
        if (status != APR_SUCCESS) {
            printf("\n");
            break;
        }

        if (APR_SUCCESS != device_tokenize_to_argv(result, &args, &offsets, &states, &state, &error, d->tpool)) {
            apr_file_printf(d->err, "syntax error at '%c' (line %" APR_SIZE_T_FMT
                    " column %ld)\n", *error, lines + 1, (apr_size_t)(error - result + 1));
        }

        else if (args[0]) {

            if (APR_EOF == device_command(d, args, offsets, lines)) {
                printf("\n");
                break;
            }

        }

        lines++;

        apr_pool_clear(d->tpool);
    }

    return 0;
}
