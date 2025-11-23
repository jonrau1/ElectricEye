#This file is part of ElectricEye.
#SPDX-License-Identifier: Apache-2.0

#Licensed to the Apache Software Foundation (ASF) under one
#or more contributor license agreements.  See the NOTICE file
#distributed with this work for additional information
#regarding copyright ownership.  The ASF licenses this file
#to you under the Apache License, Version 2.0 (the
#"License"); you may not use this file except in compliance
#with the License.  You may obtain a copy of the License at

#http://www.apache.org/licenses/LICENSE-2.0

#Unless required by applicable law or agreed to in writing,
#software distributed under the License is distributed on an
#"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
#KIND, either express or implied.  See the License for the
#specific language governing permissions and limitations
#under the License.

from functools import wraps

class CheckRegister(object):
    checks = {}

    def register_check(self, service_name):
        """Decorator registers event handlers

        Args:
            event_type: A string that matches the event type the wrapped function
            will process.
        """

        def decorator_register(func):
            if service_name not in self.checks:
                self.checks[service_name] = {func.__name__: func}
            else:
                self.checks[service_name].update({func.__name__: func})

            @wraps(func)
            def func_wrapper(*args, **kwargs):
                return func(*args, **kwargs)

            return func_wrapper

        return decorator_register

# Ancient function used for a few Auditor Caches like AWS CloudFront - refactored nearly 5 years later for shits and giggles
def accumulate_paged_results(page_iterator, key):
    """
    Accumulate paginated results efficiently
    
    Performance: Pre-allocate list and use list comprehension for better memory efficiency
    """
    # Collect all pages first, then flatten - more efficient than repeated extend()
    all_pages = [page[key] for page in page_iterator]
    
    # Flatten using itertools.chain for better performance than nested loops
    from itertools import chain
    return {key: list(chain.from_iterable(all_pages))}