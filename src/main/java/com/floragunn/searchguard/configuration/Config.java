package com.floragunn.searchguard.configuration;

import java.util.HashMap;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

public class Config {

    public Dynamic dynamic;

    
    
    @Override
    public String toString() {
        return "Config [dynamic=" + dynamic + "]";
    }

    public static class Dynamic {

        
        @JsonProperty(value="filtered_alias_mode")
        public String filtered_alias_mode;
        public Kibana kibana;
        public Http http;;
        public Authc authc;
        public Authz authz;
    
        @Override
        public String toString() {
            return "Dynamic [filtered_alias_mode=" + filtered_alias_mode + ", kibana=" + kibana + ", http=" + http + ", authc=" + authc + ", authz="
                    + authz + "]";
        }
    }

    public static class Kibana {
        
        @JsonProperty(value="multitenancy_enabled")
        public boolean multitenancy_enabled;
        public String server_username;
        public String index;
        public boolean do_not_fail_on_forbidden;
        
    }
    
    public static class Http {
        public boolean anonymous_auth_enabled;
        public Xff xff;
    }
    
    public static class Xff {
        public boolean enabled;
        public String internalProxies;
        public String remoteIpHeader;
        public String proxiesHeader;
        public String trustedProxies;
    }
    
    public static class Authc {
        
        @JsonIgnore
        private final Map<String, AuthcDomain> domains = new HashMap<>();

        @JsonAnySetter
        void setDomains(String key, AuthcDomain value) {
            domains.put(key, value);
        }

        @JsonAnyGetter
        Map<String, AuthcDomain> getDomains() {
            return domains;
        }
        
    }
    
    public static class AuthcDomain {
        public boolean http_enabled;
        public boolean transport_enabled;
        public boolean enabled;
        public int order;
        public HttpAuthenticator http_authenticator;
        public Backend authentication_backend;
    }

    public static class HttpAuthenticator {
        public boolean challenge;
        public String type;
        public Map<String, Object> config;
    }
    
    public static class Backend {
        public String type;
        public Map<String, Object> config;
    }
    
    public static class Authz {
        @JsonIgnore
        private final Map<String, AuthzDomain> domains = new HashMap<>();

        @JsonAnySetter
        void setDomains(String key, AuthzDomain value) {
            domains.put(key, value);
        }

        @JsonAnyGetter
        Map<String, AuthzDomain> getDomains() {
            return domains;
        }
    }
    
    public static class AuthzDomain {
        public boolean http_enabled;
        public boolean transport_enabled;
        public boolean enabled;
        public int order;
        public Backend authorization_backend;
    }
   
}