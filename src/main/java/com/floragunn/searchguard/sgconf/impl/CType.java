package com.floragunn.searchguard.sgconf.impl;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import com.floragunn.searchguard.sgconf.impl.v6.ActionGroups;
import com.floragunn.searchguard.sgconf.impl.v6.Config;
import com.floragunn.searchguard.sgconf.impl.v6.InternalUser;
import com.floragunn.searchguard.sgconf.impl.v6.Role;
import com.floragunn.searchguard.sgconf.impl.v6.RoleMappings;

public enum CType {
    
    INTERNALUSERS(toMap(1, InternalUser.class)),
    ACTIONGROUPS(toMap(0, List.class, 1, ActionGroups.class)),
    CONFIG(toMap(1, Config.class)),
    ROLES(toMap(1, Role.class)),
    ROLESMAPPING(toMap(1, RoleMappings.class)),
    TENANTS(toMap(1, Role.class));
    
    private Map<Integer, Class<?>> implementations;

    private CType(Map<Integer, Class<?>> implementations) {
        this.implementations = implementations;
    }

    public Map<Integer, Class<?>> getImplementationClass() {
        return Collections.unmodifiableMap(implementations);
    }
    
    public static CType fromString(String value) {
        return CType.valueOf(value.toUpperCase());
    }
    
    public String toLCString() {
        return this.toString().toLowerCase();
    }
    
    public static Config getConfig(SgDynamicConfiguration<?> sdc) {
        @SuppressWarnings("unchecked")
        SgDynamicConfiguration<Config> c = (SgDynamicConfiguration<Config>) sdc;
        return c.getCEntry("searchguard");
    }
    
    public static Set<String> lcStringValues() {
        return Arrays.stream(CType.values()).map(c->c.toLCString()).collect(Collectors.toSet());
    }
    
    public static Set<CType> fromStringValues(String[] strings) {
        return Arrays.stream(strings).map(c->CType.fromString(c)).collect(Collectors.toSet());
    }
    
    private static Map<Integer, Class<?>> toMap(Object... objects) {
        Map<Integer, Class<?>> map = new HashMap<Integer, Class<?>>();
        for(int i=0; i<objects.length;i=i+2) {
            map.put((Integer)objects[i], (Class<?>)objects[i+1]);
        }
        return Collections.unmodifiableMap(map);
    }
}

