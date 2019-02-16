package com.floragunn.searchguard.configuration;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonIgnore;

public class Role {

    private boolean readonly;
    private boolean hidden;
    private List<String> cluster;
    private Map<String, String> tenants;
    private Map<String, Index> indices;

    public static class Index {

        @JsonIgnore
        private final Map<String, List<String>> types = new HashMap<>();

        @JsonAnySetter
        void setTypes(String key, List<String> value) {
            types.put(key, value);
        }

        @JsonAnyGetter
        Map<String, List<String>> getTypes() {
            return types;
        }

        @Override
        public String toString() {
            return "Index [types=" + types + "]";
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

    public List<String> getCluster() {
        return cluster;
    }

    public void setCluster(List<String> cluster) {
        this.cluster = cluster;
    }

    public Map<String, String> getTenants() {
        return tenants;
    }

    public void setTenants(Map<String, String> tenants) {
        this.tenants = tenants;
    }

    public Map<String, Index> getIndices() {
        return indices;
    }

    public void setIndices(Map<String, Index> indices) {
        this.indices = indices;
    }

    @Override
    public String toString() {
        return "Role [readonly=" + readonly + ", hidden=" + hidden + ", cluster=" + cluster + ", tenants=" + tenants + ", indices=" + indices + "]";
    }

}