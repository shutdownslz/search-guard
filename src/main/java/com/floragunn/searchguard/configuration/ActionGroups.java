package com.floragunn.searchguard.configuration;

import java.util.List;

public class ActionGroups {

   
    private boolean readonly;
    private boolean hidden;
    private List<String> permissions;
    
    
    
    public ActionGroups() {
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
    public List<String> getPermissions() {
        return permissions;
    }
    public void setPermissions(List<String> permissions) {
        this.permissions = permissions;
    }
    
    

}