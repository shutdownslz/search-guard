package com.floragunn.searchguard;

import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.common.settings.Settings;

import com.floragunn.searchguard.auth.AuthenticationBackend;
import com.floragunn.searchguard.user.AuthCredentials;
import com.floragunn.searchguard.user.User;

public class DummyAuthenticationBackend implements AuthenticationBackend {
    
    public DummyAuthenticationBackend(final Settings settings) {
        super();
    }

    @Override
    public String getType() {
        return "dummy_auth";
    }

    @Override
    public User authenticate(AuthCredentials credentials) throws ElasticsearchSecurityException {
        if(credentials.getUsername().equals("dummy") 
                && new String(credentials.getPassword()).equals("dummy")) {
            return new User("dummy");
        }
        
        throw new ElasticsearchSecurityException("Cannot authenticate "+credentials.getUsername());
    }

    @Override
    public boolean exists(User user) {
        return user.getName().equals("dummy");
    }

}
