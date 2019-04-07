package com.floragunn.searchguard.sgconf.impl.v7;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.floragunn.searchguard.sgconf.Hashed;
import com.floragunn.searchguard.sgconf.Hideable;
import com.floragunn.searchguard.sgconf.impl.v6.InternalUserV6;

public class InternalUserV7 implements Hideable, Hashed {
        
        private String hash;
        private boolean readonly;
        private boolean hidden;
        private List<String> backend_roles = Collections.emptyList();
        private Map<String, String> attributes = Collections.emptyMap();
        private String description;

        private InternalUserV7(String hash, boolean readonly, boolean hidden, List<String> backend_roles, Map<String, String> attributes) {
            super();
            this.hash = hash;
            this.readonly = readonly;
            this.hidden = hidden;
            this.backend_roles = backend_roles;
            this.attributes = attributes;
        }

        public InternalUserV7() {
            super();
            //default constructor
        }
        
        public InternalUserV7(InternalUserV6 u6) {
            hash = u6.getHash();
            readonly = u6.isReadonly();
            hidden = u6.isHidden();
            backend_roles = u6.getRoles();
            attributes = u6.getAttributes();
            description = "Migrated from v6";
        }

        public String getHash() {
            return hash;
        }
        public void setHash(String hash) {
            this.hash = hash;
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
       

        public List<String> getBackend_roles() {
            return backend_roles;
        }

        public void setBackend_roles(List<String> backend_roles) {
            this.backend_roles = backend_roles;
        }

        public Map<String, String> getAttributes() {
            return attributes;
        }
        public void setAttributes(Map<String, String> attributes) {
            this.attributes = attributes;
        }

        @Override
        public String toString() {
            return "SgInternalUser [hash=" + hash + ", readonly=" + readonly + ", hidden=" + hidden + ", backend_roles=" + backend_roles + ", attributes="
                    + attributes + "]";
        }

        @Override
        @JsonIgnore
        public void clearHash() {
            hash = "";
        }

        public String getDescription() {
            return description;
        }

        public void setDescription(String description) {
            this.description = description;
        }
        
        

    }