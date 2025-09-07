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
 * Common utility functions for all tools.
 */

#include "device_util.h"

#include <apr_escape.h>


const char *device_pescape_shell(apr_pool_t *p, const char *str)
{

     str = apr_pescape_shell(p, str);

     if (str) {
          int i;
          int count = 0;

          /* count spaces */
          for (i = 0; str[i]; i++) {
               if (str[i] == ' ') {
                    count++;
               }
          }

          /* escape spaces */
          if (count) {

               char *d;
              const char *s;

              s = str;
              d = apr_palloc(p, strlen(str) + count + 1);
              str = d;

            for (; *s; ++s) {
                 if (*s == ' ') {
                      *d++ = '\\';
                 }
                  *d++ = *s;
            }

            *d = 0;

          }
     }

     return str;
}

