package com.floragunn.searchguard.sgconf;

import java.nio.file.Path;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map.Entry;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.XContentType;

import com.floragunn.searchguard.auth.AuthDomain;
import com.floragunn.searchguard.auth.AuthenticationBackend;
import com.floragunn.searchguard.auth.AuthorizationBackend;
import com.floragunn.searchguard.auth.Destroyable;
import com.floragunn.searchguard.auth.HTTPAuthenticator;
import com.floragunn.searchguard.auth.internal.InternalAuthenticationBackend;
import com.floragunn.searchguard.sgconf.impl.v7.ConfigV7;
import com.floragunn.searchguard.sgconf.impl.v7.ConfigV7.Authc;
import com.floragunn.searchguard.sgconf.impl.v7.ConfigV7.AuthcDomain;
import com.floragunn.searchguard.sgconf.impl.v7.ConfigV7.Authz;
import com.floragunn.searchguard.sgconf.impl.v7.ConfigV7.AuthzDomain;
import com.floragunn.searchguard.support.ReflectionHelper;

public class DynamicConfigModelV7 extends DynamicConfigModel {
    
    private final ConfigV7 config;
    private final Settings esSettings;
    private final Path configPath;
    private SortedSet<AuthDomain> restAuthDomains;
    private Set<AuthorizationBackend> restAuthorizers;
    private SortedSet<AuthDomain> transportAuthDomains;
    private Set<AuthorizationBackend> transportAuthorizers;
    private List<Destroyable> destroyableComponents;
    private final InternalAuthenticationBackend iab;
    
    public DynamicConfigModelV7(ConfigV7 config, Settings esSettings, Path configPath, InternalAuthenticationBackend iab) {
        super();
        this.config = config;
        this.esSettings =  esSettings;
        this.configPath = configPath;
        this.iab = iab;
        buildAAA();
    }
    @Override
    public SortedSet<AuthDomain> getRestAuthDomains() {
        return Collections.unmodifiableSortedSet(restAuthDomains);
    }
    @Override
    public Set<AuthorizationBackend> getRestAuthorizers() {
        return Collections.unmodifiableSet(restAuthorizers);
    }
    @Override
    public SortedSet<AuthDomain> getTransportAuthDomains() {
        return Collections.unmodifiableSortedSet(transportAuthDomains);
    }
    @Override
    public Set<AuthorizationBackend> getTransportAuthorizers() {
        return Collections.unmodifiableSet(transportAuthorizers);
    }
    @Override
    public String getTransportUsernameAttribute() {
        return config.dynamic.transport_userrname_attribute;
    }
    @Override
    public boolean isAnonymousAuthenticationEnabled() {
        return config.dynamic.http.anonymous_auth_enabled;
    }
    @Override
    public boolean isXffEnabled() {
        return config.dynamic.http.xff.enabled;
    }
    @Override
    public String getInternalProxies() {
        return config.dynamic.http.xff.internalProxies;
    }
    @Override
    public String getProxiesHeader() {
        return config.dynamic.http.xff.proxiesHeader;
    }
    @Override
    public String getRemoteIpHeader() {
        return config.dynamic.http.xff.remoteIpHeader;
    }
    @Override
    public String getTrustedProxies() {
        return config.dynamic.http.xff.trustedProxies;
    }
    @Override
    public boolean isRestAuthDisabled() {
        return config.dynamic.disable_rest_auth;
    }
    @Override
    public boolean isInterTransportAuthDisabled() {
        return config.dynamic.disable_intertransport_auth;
    }
    @Override
    public boolean isRespectRequestIndicesEnabled() {
        return config.dynamic.respect_request_indices_options;
    }
    @Override
    public String getKibanaServerUsername() {
        return config.dynamic.kibana.server_username;
    }
    @Override
    public String getKibanaIndexname() {
        return config.dynamic.kibana.index;
    }
    @Override
    public boolean isKibanaMultitenancyEnabled() {
        return config.dynamic.kibana.multitenancy_enabled;
    }
    @Override
    public boolean isDnfofEnabled() {
        return config.dynamic.do_not_fail_on_forbidden;
    }
    @Override
    public boolean isMultiRolespanEnabled() {
        return config.dynamic.multi_rolespan_enabled;
    }
    @Override
    public String getFilteredAliasMode() {
        return config.dynamic.filtered_alias_mode;
    }

    @Override
    public String getHostsResolverMode() {
        return config.dynamic.hosts_resolver_mode;
    }
    private void buildAAA() {
        
        final SortedSet<AuthDomain> restAuthDomains0 = new TreeSet<>();
        final Set<AuthorizationBackend> restAuthorizers0 = new HashSet<>();
        final SortedSet<AuthDomain> transportAuthDomains0 = new TreeSet<>();
        final Set<AuthorizationBackend> transportAuthorizers0 = new HashSet<>();
        final List<Destroyable> destroyableComponents0 = new LinkedList<>();

        final Authz authzDyn = config.dynamic.authz;

        for (final Entry<String, AuthzDomain> ad : authzDyn.getDomains().entrySet()) {
            final boolean httpEnabled = ad.getValue().http_enabled;
            final boolean transportEnabled = ad.getValue().transport_enabled;


            if (httpEnabled || transportEnabled) {
                try {

                    final String authzBackendClazz = ad.getValue().authorization_backend.type;
                    final AuthorizationBackend authorizationBackend;
                    
                    if(authzBackendClazz.equals(InternalAuthenticationBackend.class.getName()) //NOSONAR
                            || authzBackendClazz.equals("internal")
                            || authzBackendClazz.equals("intern")) {
                        authorizationBackend = iab;
                        ReflectionHelper.addLoadedModule(InternalAuthenticationBackend.class);
                    } else {
                        authorizationBackend = newInstance(
                                authzBackendClazz,"z",
                                Settings.builder()
                                .put(esSettings)
                                //.putProperties(ads.getAsStringMap(DotPath.of("authorization_backend.config")), DynamicConfiguration.checkKeyFunction()).build(), configPath);
                                .put(Settings.builder().loadFromSource(ad.getValue().authorization_backend.configAsJson(), XContentType.JSON).build()).build()
                                , configPath);
                    }
                    
                    if (httpEnabled) {
                        restAuthorizers0.add(authorizationBackend);
                    }

                    if (transportEnabled) {
                        transportAuthorizers0.add(authorizationBackend);
                    }
                    
                    if (authorizationBackend instanceof Destroyable) {
                        destroyableComponents0.add((Destroyable) authorizationBackend);
                    }
                } catch (final Exception e) {
                    log.error("Unable to initialize AuthorizationBackend {} due to {}", ad, e.toString(),e);
                }
            }
        }

        final Authc authcDyn = config.dynamic.authc;

        for (final Entry<String, AuthcDomain> ad : authcDyn.getDomains().entrySet()) {
            final boolean httpEnabled = ad.getValue().http_enabled;
            final boolean transportEnabled = ad.getValue().transport_enabled;

            if (httpEnabled || transportEnabled) {
                try {
                    AuthenticationBackend authenticationBackend;
                    final String authBackendClazz = ad.getValue().authentication_backend.type;
                    if(authBackendClazz.equals(InternalAuthenticationBackend.class.getName()) //NOSONAR
                            || authBackendClazz.equals("internal")
                            || authBackendClazz.equals("intern")) {
                        authenticationBackend = iab;
                        ReflectionHelper.addLoadedModule(InternalAuthenticationBackend.class);
                    } else {
                        authenticationBackend = newInstance(
                                authBackendClazz,"c",
                                Settings.builder()
                                .put(esSettings)
                                //.putProperties(ads.getAsStringMap(DotPath.of("authentication_backend.config")), DynamicConfiguration.checkKeyFunction()).build()
                                .put(Settings.builder().loadFromSource(ad.getValue().authentication_backend.configAsJson(), XContentType.JSON).build()).build()
                                , configPath);
                    }

                    String httpAuthenticatorType = ad.getValue().http_authenticator.type; //no default
                    HTTPAuthenticator httpAuthenticator = httpAuthenticatorType==null?null:  (HTTPAuthenticator) newInstance(httpAuthenticatorType,"h",
                            Settings.builder().put(esSettings)
                            //.putProperties(ads.getAsStringMap(DotPath.of("http_authenticator.config")), DynamicConfiguration.checkKeyFunction()).build(), 
                            .put(Settings.builder().loadFromSource(ad.getValue().http_authenticator.configAsJson(), XContentType.JSON).build()).build()

                            , configPath);

                    final AuthDomain _ad = new AuthDomain(authenticationBackend, httpAuthenticator,
                            ad.getValue().http_authenticator.challenge, ad.getValue().order);

                    if (httpEnabled && _ad.getHttpAuthenticator() != null) {
                        restAuthDomains0.add(_ad);
                    }

                    if (transportEnabled) {
                        transportAuthDomains0.add(_ad);
                    }
                    
                    if (httpAuthenticator instanceof Destroyable) {
                        destroyableComponents0.add((Destroyable) httpAuthenticator);
                    }
                    
                    if (authenticationBackend instanceof Destroyable) {
                        destroyableComponents0.add((Destroyable) authenticationBackend);
                    }
                    
                } catch (final Exception e) {
                    log.error("Unable to initialize auth domain {} due to {}", ad, e.toString(), e);
                }

            }
        }

        List<Destroyable> originalDestroyableComponents = destroyableComponents;
        
        restAuthDomains = Collections.unmodifiableSortedSet(restAuthDomains0);
        transportAuthDomains = Collections.unmodifiableSortedSet(transportAuthDomains0);
        restAuthorizers = Collections.unmodifiableSet(restAuthorizers0);
        transportAuthorizers = Collections.unmodifiableSet(transportAuthorizers0);
        
        destroyableComponents = Collections.unmodifiableList(destroyableComponents0);
        
        if(originalDestroyableComponents != null) {
            destroyDestroyables(originalDestroyableComponents);
        }
        
        originalDestroyableComponents = null;

    }
    
    private void destroyDestroyables(List<Destroyable> destroyableComponents) {
        for (Destroyable destroyable : destroyableComponents) {
            try {
                destroyable.destroy();
            } catch (Exception e) {
                log.error("Error while destroying " + destroyable, e);
            }
        }
    }
    
    private <T> T newInstance(final String clazzOrShortcut, String type, final Settings settings, final Path configPath) {

        String clazz = clazzOrShortcut;
        boolean isEnterprise = false;

        if(authImplMap.containsKey(clazz+"_"+type)) {
            clazz = authImplMap.get(clazz+"_"+type);
        } else {
            isEnterprise = true;
        }

        if(ReflectionHelper.isEnterpriseAAAModule(clazz)) {
            isEnterprise = true;
        }

        return ReflectionHelper.instantiateAAA(clazz, settings, configPath, isEnterprise);
    }
}
