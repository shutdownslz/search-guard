package com.floragunn.searchguard.sgconf.impl.v7;

import java.util.Collections;
import java.util.List;

import com.floragunn.searchguard.sgconf.Hideable;

public class TenantV7 implements Hideable {

    private boolean readonly;
    private boolean hidden;
    private List<String> applications = Collections.emptyList();
    private String description;
    
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
    public List<String> getApplications() {
        return applications;
    }
    public void setApplications(List<String> applications) {
        this.applications = applications;
    }
    public String getDescription() {
        return description;
    }
    public void setDescription(String description) {
        this.description = description;
    }
}