package com.floragunn.searchguard.configuration;

import java.util.List;
import java.util.Map;

public class InternalUsers {
        
        private String hash;
        private boolean readonly;
        private boolean hidden;
        private List<String> roles;
        private Map<String, String> attributes;

        public InternalUsers(String hash, boolean readonly, boolean hidden, List<String> roles, Map<String, String> attributes) {
            super();
            this.hash = hash;
            this.readonly = readonly;
            this.hidden = hidden;
            this.roles = roles;
            this.attributes = attributes;
        }

        public InternalUsers() {
            super();
            //default constructor
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
        public List<String> getRoles() {
            return roles;
        }
        public void setRoles(List<String> roles) {
            this.roles = roles;
        }
        public Map<String, String> getAttributes() {
            return attributes;
        }
        public void setAttributes(Map<String, String> attributes) {
            this.attributes = attributes;
        }

        @Override
        public String toString() {
            return "SgInternalUser [hash=" + hash + ", readonly=" + readonly + ", hidden=" + hidden + ", roles=" + roles + ", attributes="
                    + attributes + "]";
        }

    }