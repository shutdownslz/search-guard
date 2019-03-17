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

package com.floragunn.searchguard.support;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public final class SgUtils {
    
    protected final static Logger log = LogManager.getLogger(SgUtils.class);
    public static Locale EN_Locale = forEN();
    
    private SgUtils() {
    }
    
    //https://github.com/tonywasher/bc-java/commit/ee160e16aa7fc71330907067c5470e9bf3e6c383
    //The Legion of the Bouncy Castle Inc
    private static Locale forEN()
    {
        if ("en".equalsIgnoreCase(Locale.getDefault().getLanguage()))
        {
            return Locale.getDefault();
        }

        Locale[] locales = Locale.getAvailableLocales();
        for (int i = 0; i != locales.length; i++)
        {
            if ("en".equalsIgnoreCase(locales[i].getLanguage()))
            {
                return locales[i];
            }
        }

        return Locale.getDefault();
    }

    public static Set<String> getIndexPatterns(final Map<String,Set<String>> map, final String concreteIndex) {

        if (map == null) {
            return null;
        }

        assert map.get("_all") == null;

        final Set<String> ret = new HashSet<>(map.size()*3);
        
        //regex
        for(final Entry<String, Set<String>> entry: map.entrySet()) {
            if(WildcardMatcher.match(entry.getKey(), concreteIndex)) {
                ret.addAll(entry.getValue());
            }
        }

        return ret.size()==0?null:Collections.unmodifiableSet(ret);
    }
    
    @SafeVarargs
    public static <T> Map<T, T>  mapFromArray(T ... keyValues) {
        if(keyValues == null) {
            return Collections.emptyMap();
        }
        if (keyValues.length % 2 != 0) {
            log.error("Expected even number of key/value pairs, got {}.", Arrays.toString(keyValues));
            return null;
        }
        Map<T, T> map = new HashMap<>();
        
        for(int i = 0; i<keyValues.length; i+=2) {
            map.put(keyValues[i], keyValues[i+1]);
        }
        return map;
    }
}
