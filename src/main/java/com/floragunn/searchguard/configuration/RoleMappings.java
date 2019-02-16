package com.floragunn.searchguard.configuration;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonProperty;

public class RoleMappings {

    private boolean readonly;
    private boolean hidden;
    private List<String> backendroles;
    private List<String> hosts;
    private List<String> users;
    private List<String> andBackendroles;
    
    
    
    
    public RoleMappings() {
        super();
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
    public List<String> getBackendroles() {
        return backendroles;
    }
    public void setBackendroles(List<String> backendroles) {
        this.backendroles = backendroles;
    }
    public List<String> getHosts() {
        return hosts;
    }
    public void setHosts(List<String> hosts) {
        this.hosts = hosts;
    }
    public List<String> getUsers() {
        return users;
    }
    public void setUsers(List<String> users) {
        this.users = users;
    }
    
    @JsonProperty(value="and_backendroles")
    public List<String> getAndBackendroles() {
        return andBackendroles;
    }
    public void setAndBackendroles(List<String> andBackendroles) {
        this.andBackendroles = andBackendroles;
    }
    

}