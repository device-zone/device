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
 * Use libedit for command line handling.
 */

#include "device_libedit.h"

#include "config.h"
#include "device.h"

#ifdef HAVE_HISTEDIT_H

#include <stdlib.h>
#include <histedit.h>

#include <apr_escape.h>
#include <apr_strings.h>

static apr_status_t cleanup_editline(void *dummy)
{
    el_end(dummy);

    return APR_SUCCESS;
}

static apr_status_t cleanup_history(void *dummy)
{
    history_end(dummy);

    return APR_SUCCESS;
}

static char *prompt(EditLine *el __attribute__((__unused__)))
{
    device_t *d;

    el_get(el, EL_CLIENTDATA, &d);

    return apr_psprintf(d->tpool, "\1\033[1;37m\1(device)\1\033[0m\1 \1\033[1;32m\1%s@%s\1\033[0m\1 /%s> ",
            d->user, d->hostname, d->args ? apr_array_pstrcat(d->tpool, d->args, ' ') : "");
}

static void display_list(EditLine *el, apr_array_header_t *list, apr_ssize_t maxlen)
{
    device_t *d;
    int screenwidth;
    apr_ssize_t cols, col, lines, line;

    el_get(el, EL_CLIENTDATA, &d);
    el_get(el, EL_GETTC, "co", &screenwidth);

    cols = (size_t)screenwidth / (maxlen + 2);
    if (cols == 0) {
        cols = 1;
    }

    /* how many lines of output, rounded up */
    lines = (list->nelts + cols - 1) / cols;

    apr_file_printf(d->out, "\n");

    for (line = 0; line < lines; line++) {
        for (col = 0; col < cols; col++) {
            const char *entry;
            int current;

            current = line + col * lines;

            if (current >= list->nelts) {
                break;
            }

            entry = APR_ARRAY_IDX(list, current, const char *);

            apr_file_printf(d->out, "%s%s",
                    col == 0 ? "" : " ", entry);
            apr_file_printf(d->out, "%-*s",
                    (int) (maxlen - strlen(entry)), "");
        }
        apr_file_printf(d->out, "\n");
     }


}

static unsigned char
device_completion_hook(EditLine *el, int ch __attribute__((__unused__)))
{
    device_t *d;
    apr_pool_t *pool = NULL;
    const char **args;
    device_offset_t *offsets;
    device_tokenize_state_t *states;
    device_tokenize_state_t state = { 0 };
    const char *error;

    const LineInfo *lf = el_line(el);
    device_parse_t *current;
    apr_status_t status;
    int res = CC_ERROR;
    int i;

    el_get(el, EL_CLIENTDATA, &d);

    if (APR_SUCCESS != device_tokenize_to_argv(apr_pstrndup(d->tpool, lf->buffer, lf->cursor - lf->buffer),
            &args, &offsets, &states, &state, &error, d->tpool)) {

        /* do nothing */

    }

    else if (APR_SUCCESS == (status = device_complete(d, args, offsets, state, &current, &pool))) {

        if (current->type == DEVICE_PARSE_AMBIGUOUS) {

            int count = current->a.containers->nelts + current->a.commands->nelts + current->a.builtins->nelts;
            apr_array_header_t *list = apr_array_make(d->tpool, count, sizeof(char *));
            apr_ssize_t maxlen = 0;
            apr_ssize_t len;

            for (i = 0; i < current->a.containers->nelts; i++)
            {
                const device_name_t
                    *name = &APR_ARRAY_IDX(current->a.containers, i, const device_name_t);

                char **entry = apr_array_push(list);
                const char *n = device_pescape_shell(pool, name->name);
                *entry = apr_pstrcat(pool, "\033[34m", n, "\033[0m ", NULL);

                len = strlen(n);
                if (len > maxlen) {
                    maxlen = len;
                }

            }

            for (i = 0; i < current->a.commands->nelts; i++)
            {
                const device_name_t *name = &APR_ARRAY_IDX(current->a.commands, i, const device_name_t);

                char **entry = apr_array_push(list);
                const char *n = device_pescape_shell(pool, name->name);
                *entry = apr_pstrcat(pool, "\033[1;34m", n, "\033[0m ", NULL);

                len = strlen(n);
                if (len > maxlen) {
                    maxlen = len;
                }

            }

            for (i = 0; i < current->a.builtins->nelts; i++)
            {
                const device_name_t *name = &APR_ARRAY_IDX(current->a.builtins, i, const device_name_t);

                char **entry = apr_array_push(list);
                const char *n = device_pescape_shell(pool, name->name);
                *entry = apr_pstrcat(pool, "\033[34m", n, "\033[0m ", NULL);

                len = strlen(n);
                if (len > maxlen) {
                    maxlen = len;
                }

            }

            for (i = 0; i < current->a.keys->nelts; i++)
            {
                const device_name_t *name = &APR_ARRAY_IDX(current->a.keys, i, const device_name_t);

                char **entry = apr_array_push(list);
                const char *n = device_pescape_shell(pool, name->name);
                *entry = apr_pstrcat(pool, "\033[35m", n, "\033[0m ", NULL);

                len = strlen(n);
                if (len > maxlen) {
                    maxlen = len;
                }

            }

            for (i = 0; i < current->a.requires->nelts; i++)
            {
                const device_name_t *name = &APR_ARRAY_IDX(current->a.requires, i, const device_name_t);

                char **entry = apr_array_push(list);
                const char *n = device_pescape_shell(pool, name->name);
                *entry = apr_pstrcat(pool, "\033[1;35m", n, "\033[0m ", NULL);

                len = strlen(n);
                if (len > maxlen) {
                    maxlen = len;
                }

            }

            for (i = 0; i < current->a.values->nelts; i++)
            {
                const device_name_t *name = &APR_ARRAY_IDX(current->a.values, i, const device_name_t);

                char **entry = apr_array_push(list);
                const char *n = device_pescape_shell(pool, name->name);
                *entry = apr_pstrcat(pool, "\033[1;35m", n, "\033[0m ", NULL);

                len = strlen(n);
                if (len > maxlen) {
                    maxlen = len;
                }

            }

            display_list(el, list, maxlen);

            res = CC_REDISPLAY;

        }
        else if (current->type == DEVICE_PARSE_PARAMETER) {

            if (current->p.key && current->offset->equals > -1) {
                if (current->p.value[0]) {

                    apr_size_t len = lf->cursor - lf->buffer;

                    if (current->offset && current->offset->start < len) {
                        el_deletestr(el, len - current->offset->start);
                        el_insertstr(el,
                                apr_pstrcat(pool,
                                        device_pescape_shell(pool, current->p.value),
                                        current->completion, NULL));
                    }

                    res = CC_REFRESH;

                }
                else {
                    /* key but empty value, print nothing */
                }
            }
            else {

                apr_size_t len = lf->cursor - lf->buffer;

                if (current->offset && current->offset->start < len) {
                    el_deletestr(el, len - current->offset->start);
                    el_insertstr(el,
                            apr_pstrcat(pool,
                                    device_pescape_shell(pool, current->name),
                                    current->completion, NULL));
                }

                res = CC_REFRESH;

            }

        }
        else {

            apr_size_t len = lf->cursor - lf->buffer;

            if (current->offset && current->offset->start < len) {
                el_deletestr(el, len - current->offset->start);
                el_insertstr(el,
                        apr_pstrcat(pool,
                                device_pescape_shell(pool, current->name),
                                current->completion, NULL));
            }

            res = CC_REFRESH;

        }


    }

    if (pool) {
        apr_pool_destroy(pool);
    }

    apr_pool_clear(d->tpool);

    return res;
}

int device_libedit(device_t *d, const char *name, FILE *in, FILE *out, FILE *err)
{
    apr_size_t lines = 0;

    EditLine *el = NULL;
    History *hist;
    HistEvent ev;
    const char *home = getenv("HOME");
    int num;

    int continuation = 0;

    hist = history_init();
    history(hist, &ev, H_SETSIZE, 1000);
    history(hist, &ev, H_SETUNIQUE, 1);

    apr_pool_cleanup_register(d->pool, hist, cleanup_history, cleanup_history);

    el = el_init(name, in, out, err);
    el_set(el, EL_SIGNAL, 1);
    el_set(el, EL_PROMPT_ESC, prompt, '\1');
    el_set(el, EL_HIST, history, hist);
    el_set(el, EL_CLIENTDATA, d);
    /* Add a user-defined function  */
    el_set(el, EL_ADDFN, "ed-complete", "Complete argument", device_completion_hook);
    /* Bind tab to it               */
    el_set(el, EL_BIND, "^I", "ed-complete", NULL);

    apr_pool_cleanup_register(d->pool, el, cleanup_editline, cleanup_editline);

    if (home) {
        if (APR_SUCCESS == apr_filepath_set(home, d->pool)) {
            history(hist, &ev, H_LOAD, DEVICE_HISTORY);
        }
    }

    while (1) {
        const char *result = NULL;
        const LineInfo *li;
        const char **args;
        device_offset_t *offsets;
        device_tokenize_state_t *states;
        device_tokenize_state_t state = { 0 };
        const char *error;

        do {
            result = el_gets(el, &num);
        } while ( ( result == NULL ) && ( errno == EAGAIN ) );

        if (!result) {
            fprintf(out, "\n");
            break;
        }

        li = el_line(el);

        history(hist, &ev, continuation ? H_APPEND : H_ENTER, result);

        if (APR_SUCCESS != device_tokenize_to_argv(result, &args, &offsets, &states, &state, &error, d->tpool)) {
            apr_file_printf(d->err, "syntax error at '%c' (line %" APR_SIZE_T_FMT
                    " column %ld)\n", *error, lines + 1, (error - result) + 1);
        }

        else if (args[0]) {
            if (APR_EOF == device_command(d, args, offsets, lines)) {
                fprintf(out, "\n");
                break;
            }
        }

        lines++;

        apr_pool_clear(d->tpool);
    }

    if (home) {
        if (APR_SUCCESS == apr_filepath_set(home, d->pool)) {
            history(hist, &ev, H_SAVE, DEVICE_HISTORY);
        }
    }

    return 0;
}

#endif
