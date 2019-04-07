package com.floragunn.searchguard.sgconf.impl.v7;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import com.floragunn.searchguard.sgconf.Hideable;
import com.floragunn.searchguard.sgconf.impl.v6.RoleMappingsV6;
import com.floragunn.searchguard.sgconf.impl.v6.RoleV6;
import com.google.common.collect.Lists;

public class RoleV7 implements Hideable {

    private boolean readonly;
    private boolean hidden;
    private String description;
    private List<String> cluster_permissions = Collections.emptyList();
    private List<Index> indices_permissions = Collections.emptyList();
    private Map<String, String> tenants = Collections.emptyMap();
    private List<String> applications = Collections.emptyList();
    private MapTo mapto = new MapTo();
    
    public RoleV7() {
        
    }
    
    public RoleV7(RoleV6 roleV6, RoleMappingsV6 roleMappingsV6) {
        this.readonly = roleV6.isReadonly();
        this.hidden = roleV6.isHidden();
        this.description = "Migrated from v6 (all types mapped)";
        this.cluster_permissions = roleV6.getCluster();
        this.tenants = roleV6.getTenants();
        indices_permissions = new ArrayList<>();
        for(Entry<String, RoleV6.Index> v6i: roleV6.getIndices().entrySet()) {
            indices_permissions.add(new Index(v6i.getKey(), v6i.getValue()));
        }
        
        if(roleMappingsV6 != null) {
            this.mapto = new MapTo(roleMappingsV6);
        }
    }

    public static class Index {

        private List<String> index_patterns = Collections.emptyList();
        private String dls;
        private List<String> fls = Collections.emptyList();
        private List<String> masked_fields = Collections.emptyList();
        private List<String> allowed_actions = Collections.emptyList();
        
        public Index(String pattern, RoleV6.Index v6Index) {
            super();
            index_patterns = Collections.singletonList(pattern);
            dls = v6Index.get_dls_();
            fls = v6Index.get_fls_();
            masked_fields = v6Index.get_masked_fields_();
            Set<String> tmpActions = new HashSet<>(); 
            for(Entry<String, List<String>> type: v6Index.getTypes().entrySet()) {
                tmpActions.addAll(type.getValue());
            }
            allowed_actions = new ArrayList<>(tmpActions);
        }
        
        
        public Index() {
            super();
        }
        
        public List<String> getIndex_patterns() {
            return index_patterns;
        }
        public void setIndex_patterns(List<String> index_patterns) {
            this.index_patterns = index_patterns;
        }
        public String getDls() {
            return dls;
        }
        public void setDls(String dls) {
            this.dls = dls;
        }
        public List<String> getFls() {
            return fls;
        }
        public void setFls(List<String> fls) {
            this.fls = fls;
        }
        public List<String> getMasked_fields() {
            return masked_fields;
        }
        public void setMasked_fields(List<String> masked_fields) {
            this.masked_fields = masked_fields;
        }
        public List<String> getAllowed_actions() {
            return allowed_actions;
        }
        public void setAllowed_actions(List<String> allowed_actions) {
            this.allowed_actions = allowed_actions;
        }
        @Override
        public String toString() {
            return "Index [index_patterns=" + index_patterns + ", dls=" + dls + ", fls=" + fls + ", masked_fields=" + masked_fields
                    + ", allowed_actions=" + allowed_actions + "]";
        }
    }

    public static class MapTo {
        private List<String> users = Collections.emptyList();
        private List<String> hosts = Collections.emptyList();
        private List<String> backend_roles = Collections.emptyList();
        private List<String> and_backend_roles = Collections.emptyList();
        
        public MapTo(RoleMappingsV6 roleMappingsV6) {
            super();
            users = roleMappingsV6.getUsers();
            hosts = roleMappingsV6.getHosts();
            backend_roles = roleMappingsV6.getBackendroles();
            and_backend_roles = roleMappingsV6.getAndBackendroles();
        }
        
        
        public MapTo() {
            super();
        }
        public List<String> getUsers() {
            return users;
        }
        public void setUsers(List<String> users) {
            this.users = users;
        }
        public List<String> getHosts() {
            return hosts;
        }
        public void setHosts(List<String> hosts) {
            this.hosts = hosts;
        }
        public List<String> getBackend_roles() {
            return backend_roles;
        }
        public void setBackend_roles(List<String> backend_roles) {
            this.backend_roles = backend_roles;
        }
        public List<String> getAnd_backend_roles() {
            return and_backend_roles;
        }
        public void setAnd_backend_roles(List<String> and_backend_roles) {
            this.and_backend_roles = and_backend_roles;
        }
        @Override
        public String toString() {
            return "MapTo [users=" + users + ", hosts=" + hosts + ", backend_roles=" + backend_roles + ", and_backend_roles=" + and_backend_roles
                    + "]";
        }
        
        
    }
    
    public boolean isReadonly() {
        return readonly;
    }

    public void setReadonly(boolean readonly) {
        this.readonly = readonly;
    }

    public boolean isHidden() {
        return hidden;
    }

    public void setHidden(boolean hidden) {
        this.hidden = hidden;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public List<String> getCluster_permissions() {
        return cluster_permissions;
    }

    public void setCluster_permissions(List<String> cluster_permissions) {
        this.cluster_permissions = cluster_permissions;
    }

    public List<Index> getIndices_permissions() {
        return indices_permissions;
    }

    public void setIndices_permissions(List<Index> indices_permissions) {
        this.indices_permissions = indices_permissions;
    }

    public Map<String, String> getTenants() {
        return tenants;
    }

    public void setTenants(Map<String, String> tenants) {
        if(tenants != null) {
            Set<String> valueCheck = new HashSet<>(tenants.values());
            valueCheck.removeAll(Lists.newArrayList("rW","Rw","rw", "ro","Ro","rO","implicit", "rw".toUpperCase(), "ro".toUpperCase(), "implicit".toUpperCase()));
            if(valueCheck.size() > 0) {
                throw new IllegalArgumentException("Non allowed modifiers for tenants: "+valueCheck);
            }
        }
        
        this.tenants = tenants;
    }

    public List<String> getApplications() {
        return applications;
    }

    public void setApplications(List<String> applications) {
        this.applications = applications;
    }

    public MapTo getMapto() {
        return mapto;
    }

    public void setMapto(MapTo mapto) {
        this.mapto = mapto;
    }

    @Override
    public String toString() {
        return "RoleV7 [readonly=" + readonly + ", hidden=" + hidden + ", description=" + description + ", cluster_permissions=" + cluster_permissions
                + ", indices_permissions=" + indices_permissions + ", tenants=" + tenants + ", applications=" + applications + ", mapto=" + mapto
                + "]";
    }

    

    
    

}