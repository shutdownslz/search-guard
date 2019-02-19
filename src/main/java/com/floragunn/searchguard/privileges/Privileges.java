/*
 * Copyright 2015-2018 floragunn GmbH
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

package com.floragunn.searchguard.privileges;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class Privileges {
    public static final String SG_TENANT_WRITE = "searchguard:tenant/write";

    public static class Defaults {
        public static final List<String> TENANT_RW = Collections.unmodifiableList(Arrays.asList("searchguard:tenant/write", "kibana:ui:navLinks/*"));
        public static final List<String> TENANT_RO = Collections.unmodifiableList(Arrays.asList("searchguard:tenant/read", "kibana:ui:navLinks/*"));

        public static final List<String> DEFAULT_TENANT = Collections.unmodifiableList(Arrays.asList("kibana:ui:navLinks/*"));

        public static final Set<String> SET_TENANT_RW = Collections.unmodifiableSet(new HashSet<>(TENANT_RW));
        public static final Set<String> SET_TENANT_RO = Collections.unmodifiableSet(new HashSet<>(TENANT_RO));
    }

}
