/*
 * Copyright 2015-2017 floragunn GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */

package com.floragunn.searchguard.auth.internal;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.bouncycastle.crypto.generators.OpenBSDBCrypt;
import org.elasticsearch.ElasticsearchSecurityException;

import com.floragunn.searchguard.auth.AuthenticationBackend;
import com.floragunn.searchguard.auth.AuthorizationBackend;
import com.floragunn.searchguard.configuration.ConfigurationRepository;
import com.floragunn.searchguard.sgconf.impl.CType;
import com.floragunn.searchguard.sgconf.impl.SgDynamicConfiguration;
import com.floragunn.searchguard.sgconf.impl.v6.InternalUser;
import com.floragunn.searchguard.user.AuthCredentials;
import com.floragunn.searchguard.user.User;

public class InternalAuthenticationBackend implements AuthenticationBackend, AuthorizationBackend {

    private final ConfigurationRepository configurationRepository;

    public InternalAuthenticationBackend(final ConfigurationRepository configurationRepository) {
        super();
        this.configurationRepository = configurationRepository;
    }

    @Override
    public boolean exists(User user) {

        final SgDynamicConfiguration<InternalUser> cfg = getConfigSettings();
        if (cfg == null) {
            return false;
        }
        
        InternalUser iuser = cfg.getCEntry(user.getName());
        
        if(iuser == null) {
            return false;
        }
        
        String hashed = iuser.getHash();

        if (hashed == null) {
            
            /*for(String username:cfg.names()) {
                String u = cfg.get(DotPath.of(username + ".username"));
                if(user.getName().equals(u)) {
                    hashed = cfg.get(DotPath.of(username + ".hash"));
                    break;
                }
            }
            
            if(hashed == null) {
                return false;
            }*/
            
            return false;
        }
        
        final List<String> roles = iuser.getRoles();
        
        if(roles != null) {
            user.addRoles(roles);
        }
        
        return true;
    }
    
    @Override
    public User authenticate(final AuthCredentials credentials) {
        
        final SgDynamicConfiguration<InternalUser> cfg = getConfigSettings();
        if (cfg == null) {
            throw new ElasticsearchSecurityException("Internal authentication backend not configured. May be Search Guard is not initialized. See http://docs.search-guard.com/v6/sgadmin");

        }
        
        InternalUser iuser = cfg.getCEntry(credentials.getUsername());
        
        if(iuser == null) {
            throw new ElasticsearchSecurityException(credentials.getUsername() + " not found");
        }
        
        String hashed = iuser.getHash();

        if (hashed == null) {
            
            /*for(String username:cfg.names()) {
                String u = cfg.get(DotPath.of(username + ".username"));
                if(credentials.getUsername().equals(u)) {
                    hashed = cfg.get(DotPath.of(username + ".hash"));
                    break;
                }
            }
            
            if(hashed == null) {
                throw new ElasticsearchSecurityException(credentials.getUsername() + " not found");
            }*/
            
            throw new ElasticsearchSecurityException(credentials.getUsername() + " not found");
        }
        
        final byte[] password = credentials.getPassword();
        
        if(password == null || password.length == 0) {
            throw new ElasticsearchSecurityException("empty passwords not supported");
        }

        ByteBuffer wrap = ByteBuffer.wrap(password);
        CharBuffer buf = StandardCharsets.UTF_8.decode(wrap);
        char[] array = new char[buf.limit()];
        buf.get(array);
        
        Arrays.fill(password, (byte)0);
       
        try {
            if (OpenBSDBCrypt.checkPassword(hashed, array)) {
                final List<String> roles = iuser.getRoles();
                final Map<String, String> customAttributes = iuser.getAttributes();
                if(customAttributes != null) {
                    for(Entry<String, String> attributeName: customAttributes.entrySet()) {
                        credentials.addAttribute("attr.internal."+attributeName.getKey(), attributeName.getValue());
                    }
                }

                return new User(credentials.getUsername(), roles, credentials);
            } else {
                throw new ElasticsearchSecurityException("password does not match");
            }
        } finally {
            Arrays.fill(wrap.array(), (byte)0);
            Arrays.fill(buf.array(), '\0');
            Arrays.fill(array, '\0');
        }
    }

    @Override
    public String getType() {
        return "internal";
    }

    private SgDynamicConfiguration<InternalUser> getConfigSettings() {
        return (SgDynamicConfiguration<InternalUser>) configurationRepository.getConfiguration(CType.INTERNALUSERS);
    }

    @Override
    public void fillRoles(User user, AuthCredentials credentials) throws ElasticsearchSecurityException {
        final SgDynamicConfiguration<InternalUser> cfg = getConfigSettings();
        if (cfg == null) {
            throw new ElasticsearchSecurityException("Internal authentication backend not configured. May be Search Guard is not initialized. See http://docs.search-guard.com/v6/sgadmin");

        }
        
        InternalUser iuser = cfg.getCEntry(credentials.getUsername());
        
        if(iuser != null) {
            final List<String> roles = iuser.getRoles();
            if(roles != null && !roles.isEmpty() && user != null) {
                user.addRoles(roles);
            }
        }
        
        
    }
}
