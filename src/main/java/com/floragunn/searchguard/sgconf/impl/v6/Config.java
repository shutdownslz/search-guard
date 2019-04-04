package com.floragunn.searchguard.sgconf.impl.v6;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.floragunn.searchguard.DefaultObjectMapper;
import com.floragunn.searchguard.auth.internal.InternalAuthenticationBackend;

public class Config {

    public Dynamic dynamic;

    
    
    @Override
    public String toString() {
        return "Config [dynamic=" + dynamic + "]";
    }

    public static class Dynamic {


        public String filtered_alias_mode = "warn";
        public boolean disable_rest_auth;
        public boolean disable_intertransport_auth;
        public boolean respect_request_indices_options;
        public String license;
        public Kibana kibana = new Kibana();
        public Http http = new Http();
        public Authc authc = new Authc();
        public Authz authz = new Authz();
        public boolean do_not_fail_on_forbidden;
        public boolean multi_rolespan_enabled;
        public String hosts_resolver_mode = "ip-only";
        public String transport_userrname_attribute;
    
        @Override
        public String toString() {
            return "Dynamic [filtered_alias_mode=" + filtered_alias_mode + ", kibana=" + kibana + ", http=" + http + ", authc=" + authc + ", authz="
                    + authz + "]";
        }
    }

    public static class Kibana {

        public boolean multitenancy_enabled = true;
        public String server_username = "kibanaserver";
        public String index = ".kibana";
        public boolean do_not_fail_on_forbidden;
        
    }
    
    public static class Http {
        public boolean anonymous_auth_enabled = false;
        public Xff xff = new Xff();
    }
    
    public static class Xff {
        public boolean enabled = true;
        public String internalProxies = Pattern.compile(
                "10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|" +
                        "192\\.168\\.\\d{1,3}\\.\\d{1,3}|" +
                        "169\\.254\\.\\d{1,3}\\.\\d{1,3}|" +
                        "127\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|" +
                        "172\\.1[6-9]{1}\\.\\d{1,3}\\.\\d{1,3}|" +
                        "172\\.2[0-9]{1}\\.\\d{1,3}\\.\\d{1,3}|" +
                        "172\\.3[0-1]{1}\\.\\d{1,3}\\.\\d{1,3}").toString();
        public String remoteIpHeader="X-Forwarded-For";
        public String proxiesHeader="X-Forwarded-By";
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
        public Map<String, AuthcDomain> getDomains() {
            return domains;
        }
        
    }
    
    public static class AuthcDomain {
        public boolean http_enabled= true;
        public boolean transport_enabled= true;
        public boolean enabled= true;
        public int order = 0;
        public HttpAuthenticator http_authenticator = new HttpAuthenticator();
        public AuthcBackend authentication_backend = new AuthcBackend();
    }

    public static class HttpAuthenticator {
        public boolean challenge = true;
        public String type;
        public Map<String, Object> config = Collections.emptyMap();
        
        @JsonIgnore
        public String configAsJson() {
            try {
                return DefaultObjectMapper.writeValueAsString(config, false);
            } catch (JsonProcessingException e) {
                throw new RuntimeException(e);
            }
        }
    }
    
    public static class AuthzBackend {
        public String type = "noop";
        public Map<String, Object> config = Collections.emptyMap();
        
        @JsonIgnore
        public String configAsJson() {
            try {
                return DefaultObjectMapper.writeValueAsString(config, false);
            } catch (JsonProcessingException e) {
                throw new RuntimeException(e);
            }
        }
    }
    
    public static class AuthcBackend {
        public String type = InternalAuthenticationBackend.class.getName();
        public Map<String, Object> config = Collections.emptyMap();
        
        @JsonIgnore
        public String configAsJson() {
            try {
                return DefaultObjectMapper.writeValueAsString(config, false);
            } catch (JsonProcessingException e) {
                throw new RuntimeException(e);
            }
        }
    }
    
    public static class Authz {
        @JsonIgnore
        private final Map<String, AuthzDomain> domains = new HashMap<>();

        @JsonAnySetter
        void setDomains(String key, AuthzDomain value) {
            domains.put(key, value);
        }

        @JsonAnyGetter
        public Map<String, AuthzDomain> getDomains() {
            return domains;
        }
    }
    
    public static class AuthzDomain {
        public boolean http_enabled = true;
        public boolean transport_enabled = true;
        public boolean enabled = true;
        public int order;
        public AuthzBackend authorization_backend = new AuthzBackend();
    }
   
}