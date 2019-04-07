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

package com.floragunn.searchguard.auth;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;
import java.util.concurrent.Callable;
import java.util.concurrent.TimeUnit;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.rest.BytesRestResponse;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.TransportRequest;

import com.floragunn.searchguard.auditlog.AuditLog;
import com.floragunn.searchguard.auth.internal.InternalAuthenticationBackend;
import com.floragunn.searchguard.auth.internal.NoOpAuthenticationBackend;
import com.floragunn.searchguard.auth.internal.NoOpAuthorizationBackend;
import com.floragunn.searchguard.configuration.AdminDNs;
import com.floragunn.searchguard.http.HTTPBasicAuthenticator;
import com.floragunn.searchguard.http.HTTPClientCertAuthenticator;
import com.floragunn.searchguard.http.HTTPProxyAuthenticator;
import com.floragunn.searchguard.http.XFFResolver;
import com.floragunn.searchguard.sgconf.ConfigModel;
import com.floragunn.searchguard.sgconf.DynamicConfigFactory.DCFListener;
import com.floragunn.searchguard.sgconf.DynamicConfigModel;
import com.floragunn.searchguard.sgconf.InternalUsersModel;
import com.floragunn.searchguard.ssl.util.Utils;
import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.support.HTTPHelper;
import com.floragunn.searchguard.user.AuthCredentials;
import com.floragunn.searchguard.user.User;
import com.google.common.base.Strings;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.RemovalListener;
import com.google.common.cache.RemovalNotification;

public class BackendRegistry implements DCFListener {

    protected final Logger log = LogManager.getLogger(this.getClass());
    private SortedSet<AuthDomain> restAuthDomains;
    private Set<AuthorizationBackend> restAuthorizers;
    private SortedSet<AuthDomain> transportAuthDomains;
    private Set<AuthorizationBackend> transportAuthorizers;
    //private List<Destroyable> destroyableComponents;
    private volatile boolean initialized;
    private final AdminDNs adminDns;
    private final XFFResolver xffResolver;
    private volatile boolean anonymousAuthEnabled = false;
    private final Settings esSettings;
    //private final InternalAuthenticationBackend iab;
    private final AuditLog auditLog;
    private final ThreadPool threadPool;
    private final UserInjector userInjector;
    private final int ttlInMin;
    private Cache<AuthCredentials, User> userCache; //rest standard
    private Cache<String, User> restImpersonationCache; //used for rest impersonation
    private Cache<String, User> userCacheTransport; //transport no creds, possibly impersonated
    private Cache<AuthCredentials, User> authenticatedUserCacheTransport; //transport creds, no impersonation
    
    private Cache<User, Set<String>> transportRoleCache; //
    private Cache<User, Set<String>> restRoleCache; //
    
    private volatile String transportUsernameAttribute = null;
    
    private void createCaches() {
        userCache = CacheBuilder.newBuilder()
                .expireAfterWrite(ttlInMin, TimeUnit.MINUTES)
                .removalListener(new RemovalListener<AuthCredentials, User>() {
                    @Override
                    public void onRemoval(RemovalNotification<AuthCredentials, User> notification) {
                        log.debug("Clear user cache for {} due to {}", notification.getKey().getUsername(), notification.getCause());
                    }
                }).build();

        userCacheTransport = CacheBuilder.newBuilder()
                .expireAfterWrite(ttlInMin, TimeUnit.MINUTES)
                .removalListener(new RemovalListener<String, User>() {
                    @Override
                    public void onRemoval(RemovalNotification<String, User> notification) {
                        log.debug("Clear user cache for {} due to {}", notification.getKey(), notification.getCause());
                    }
                }).build();

        authenticatedUserCacheTransport = CacheBuilder.newBuilder()
                .expireAfterWrite(ttlInMin, TimeUnit.MINUTES)
                .removalListener(new RemovalListener<AuthCredentials, User>() {
                    @Override
                    public void onRemoval(RemovalNotification<AuthCredentials, User> notification) {
                        log.debug("Clear user cache for {} due to {}", notification.getKey().getUsername(), notification.getCause());
                    }
                }).build();

        restImpersonationCache = CacheBuilder.newBuilder()
                .expireAfterWrite(ttlInMin, TimeUnit.MINUTES)
                .removalListener(new RemovalListener<String, User>() {
                    @Override
                    public void onRemoval(RemovalNotification<String, User> notification) {
                        log.debug("Clear user cache for {} due to {}", notification.getKey(), notification.getCause());
                    }
                }).build();
        
        
        
        transportRoleCache = CacheBuilder.newBuilder()
                .expireAfterWrite(ttlInMin, TimeUnit.MINUTES)
                .removalListener(new RemovalListener<User, Set<String>>() {
                    @Override
                    public void onRemoval(RemovalNotification<User, Set<String>> notification) {
                        log.debug("Clear user cache for {} due to {}", notification.getKey(), notification.getCause());
                    }
                }).build();
        
        restRoleCache = CacheBuilder.newBuilder()
                .expireAfterWrite(ttlInMin, TimeUnit.MINUTES)
                .removalListener(new RemovalListener<User, Set<String>>() {
                    @Override
                    public void onRemoval(RemovalNotification<User, Set<String>> notification) {
                        log.debug("Clear user cache for {} due to {}", notification.getKey(), notification.getCause());
                    }
                }).build();
    }

    public BackendRegistry(final Settings settings, final AdminDNs adminDns,
            final XFFResolver xffResolver, final AuditLog auditLog, final ThreadPool threadPool) {
        this.adminDns = adminDns;
        this.esSettings = settings;
        this.xffResolver = xffResolver;
        this.auditLog = auditLog;
        this.threadPool = threadPool;
        this.userInjector = new UserInjector(settings, threadPool, auditLog, xffResolver);

        this.ttlInMin = settings.getAsInt(ConfigConstants.SEARCHGUARD_CACHE_TTL_MINUTES, 60);
                
        createCaches();
    }

    public boolean isInitialized() {
        return initialized;
    }

    public void invalidateCache() {
        userCache.invalidateAll();
        userCacheTransport.invalidateAll();
        authenticatedUserCacheTransport.invalidateAll();
        restImpersonationCache.invalidateAll();
        restRoleCache.invalidateAll();
        transportRoleCache.invalidateAll();
    }

    @Override
    public void onChanged(ConfigModel cf, DynamicConfigModel dcf, InternalUsersModel cfff) {
        
        invalidateCache();

        transportUsernameAttribute = dcf.getTransportUsernameAttribute();// config.dynamic.transport_userrname_attribute;
        anonymousAuthEnabled = dcf.isAnonymousAuthenticationEnabled()//config.dynamic.http.anonymous_auth_enabled
                && !esSettings.getAsBoolean(ConfigConstants.SEARCHGUARD_COMPLIANCE_DISABLE_ANONYMOUS_AUTHENTICATION, false);

        //List<Destroyable> originalDestroyableComponents = destroyableComponents;
        
        restAuthDomains = Collections.unmodifiableSortedSet(dcf.getRestAuthDomains());
        transportAuthDomains = Collections.unmodifiableSortedSet(dcf.getTransportAuthDomains());
        restAuthorizers = Collections.unmodifiableSet(dcf.getRestAuthorizers());
        transportAuthorizers = Collections.unmodifiableSet(dcf.getTransportAuthorizers());
        //destroyableComponents = Collections.unmodifiableList(destroyableComponents0);
        
        //SG6 no default authc
        initialized = !restAuthDomains.isEmpty() || anonymousAuthEnabled;
        
        //TODO SG7 destroy componenets
        //if(originalDestroyableComponents != null) {
        //    destroyDestroyables(originalDestroyableComponents);
        //}
        
        //originalDestroyableComponents = null;
        
        /*//final ConfigV6 config = CType.getConfig(settings0);
        //dcf.getDynamicConfigModel().
        
        final SortedSet<AuthDomain> restAuthDomains0 = new TreeSet<>();
        final Set<AuthorizationBackend> restAuthorizers0 = new HashSet<>();
        final SortedSet<AuthDomain> transportAuthDomains0 = new TreeSet<>();
        final Set<AuthorizationBackend> transportAuthorizers0 = new HashSet<>();
        final List<Destroyable> destroyableComponents0 = new LinkedList<>();

        //final Authz authzDyn = config.dynamic.authz;
        final Authz authzDyn = dcf.get

        for (final Entry<String, AuthzDomain> ad : authzDyn.getDomains().entrySet()) {
            final boolean enabled = ad.getValue().enabled;
            final boolean httpEnabled = enabled && ad.getValue().http_enabled;
            final boolean transportEnabled = enabled && ad.getValue().transport_enabled;


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
            final boolean enabled = ad.getValue().enabled;
            final boolean httpEnabled = enabled && ad.getValue().http_enabled;
            final boolean transportEnabled = enabled && ad.getValue().transport_enabled;

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

        invalidateCache();

        transportUsernameAttribute = config.dynamic.transport_userrname_attribute;
        anonymousAuthEnabled = config.dynamic.http.anonymous_auth_enabled
                && !esSettings.getAsBoolean(ConfigConstants.SEARCHGUARD_COMPLIANCE_DISABLE_ANONYMOUS_AUTHENTICATION, false);

        List<Destroyable> originalDestroyableComponents = destroyableComponents;
        
        restAuthDomains = Collections.unmodifiableSortedSet(restAuthDomains0);
        transportAuthDomains = Collections.unmodifiableSortedSet(transportAuthDomains0);
        restAuthorizers = Collections.unmodifiableSet(restAuthorizers0);
        transportAuthorizers = Collections.unmodifiableSet(transportAuthorizers0);
        destroyableComponents = Collections.unmodifiableList(destroyableComponents0);
        
        //SG6 no default authc
        initialized = !restAuthDomains.isEmpty() || anonymousAuthEnabled;
        
        if(originalDestroyableComponents != null) {
            destroyDestroyables(originalDestroyableComponents);
        }
        
        originalDestroyableComponents = null;*/

    }

    public User authenticate(final TransportRequest request, final String sslPrincipal, final Task task, final String action) {

        if(log.isDebugEnabled() && request.remoteAddress() != null) {
            log.debug("Transport authentication request from {}", request.remoteAddress());
        }
        
        User origPKIUser = new User(sslPrincipal);
        
        if(adminDns.isAdmin(origPKIUser)) {
            auditLog.logSucceededLogin(origPKIUser.getName(), true, null, request, action, task);
            return origPKIUser;
        }
        
        if (!isInitialized()) {
            log.error("Not yet initialized (you may need to run sgadmin)");
            return null;
        }

        final String authorizationHeader = threadPool.getThreadContext().getHeader("Authorization");
        //Use either impersonation OR credentials authentication
        //if both is supplied credentials authentication win
        final AuthCredentials creds = HTTPHelper.extractCredentials(authorizationHeader, log);

        User impersonatedTransportUser = null;

        if(creds != null) {
            if(log.isDebugEnabled())  {
                log.debug("User {} submitted also basic credentials: {}", origPKIUser.getName(), creds);
            }
        }

        //loop over all transport auth domains
        for (final AuthDomain authDomain: transportAuthDomains) {

            
            if(log.isDebugEnabled()) {
                log.debug("Check transport authdomain {}/{} or {} in total", authDomain.getBackend().getType(), authDomain.getOrder(), transportAuthDomains.size());
            }
            
            User authenticatedUser = null;

            if(creds == null) {
                //no credentials submitted
                //impersonation possible
                impersonatedTransportUser = impersonate(request, origPKIUser);
                origPKIUser = resolveTransportUsernameAttribute(origPKIUser);
                authenticatedUser = checkExistsAndAuthz(userCacheTransport, impersonatedTransportUser==null?origPKIUser:impersonatedTransportUser, authDomain.getBackend(), transportAuthorizers);
            } else {
                 //auth credentials submitted
                //impersonation not possible, if requested it will be ignored
                authenticatedUser = authcz(authenticatedUserCacheTransport, transportRoleCache, creds, authDomain.getBackend(), transportAuthorizers);
            }

            if(authenticatedUser == null) {
                if(log.isDebugEnabled()) {
                    log.debug("Cannot authenticate transport user {} (or add roles) with authdomain {}/{} of {}, try next", creds==null?(impersonatedTransportUser==null?origPKIUser.getName():impersonatedTransportUser.getName()):creds.getUsername(), authDomain.getBackend().getType(), authDomain.getOrder(), transportAuthDomains.size());
                }
                continue;
            }

            if(adminDns.isAdmin(authenticatedUser)) {
                log.error("Cannot authenticate transport user because admin user is not permitted to login");
                auditLog.logFailedLogin(authenticatedUser.getName(), true, null, request, task);
                return null;
            }

            if(log.isDebugEnabled()) {
                log.debug("Transport user '{}' is authenticated", authenticatedUser);
            }

            auditLog.logSucceededLogin(authenticatedUser.getName(), false, impersonatedTransportUser==null?null:origPKIUser.getName(), request, action, task);

            return authenticatedUser;
        }//end looping auth domains


        //auditlog
        if(creds == null) {
            auditLog.logFailedLogin(impersonatedTransportUser==null?origPKIUser.getName():impersonatedTransportUser.getName(), false, impersonatedTransportUser==null?null:origPKIUser.getName(), request, task);
        } else {
            auditLog.logFailedLogin(creds.getUsername(), false, null, request, task);
        }
 
        log.warn("Transport authentication finally failed for {} from {}", creds == null ? impersonatedTransportUser==null?origPKIUser.getName():impersonatedTransportUser.getName():creds.getUsername(), request.remoteAddress());

        return null;
    }


    /**
     *
     * @param request
     * @param channel
     * @return The authenticated user, null means another roundtrip
     * @throws ElasticsearchSecurityException
     */
    public boolean authenticate(final RestRequest request, final RestChannel channel, final ThreadContext threadContext) {

        final String sslPrincipal = (String) threadPool.getThreadContext().getTransient(ConfigConstants.SG_SSL_PRINCIPAL);

        if(adminDns.isAdminDN(sslPrincipal)) {
            //PKI authenticated REST call
            threadPool.getThreadContext().putTransient(ConfigConstants.SG_USER, new User(sslPrincipal));
            auditLog.logSucceededLogin(sslPrincipal, true, null, request);
            return true;
        }

        if (userInjector.injectUser(request)) {
            // ThreadContext injected user
            return true;
        }
        
        if (!isInitialized()) {
            log.error("Not yet initialized (you may need to run sgadmin)");
            channel.sendResponse(new BytesRestResponse(RestStatus.SERVICE_UNAVAILABLE, "Search Guard not initialized (SG11). See http://docs.search-guard.com/v6/sgadmin"));
            return false;
        }
        
        final TransportAddress remoteAddress = xffResolver.resolve(request);
        
        if(log.isTraceEnabled()) {
            log.trace("Rest authentication request from {} [original: {}]", remoteAddress, request.getHttpChannel().getRemoteAddress());
    	}

        threadContext.putTransient(ConfigConstants.SG_REMOTE_ADDRESS, remoteAddress);

        boolean authenticated = false;

        User authenticatedUser = null;

        AuthCredentials authCredenetials = null;

        HTTPAuthenticator firstChallengingHttpAuthenticator = null;

        //loop over all http/rest auth domains
        for (final AuthDomain authDomain: restAuthDomains) {
            
            if(log.isDebugEnabled()) {
                log.debug("Check authdomain for rest {}/{} or {} in total", authDomain.getBackend().getType(), authDomain.getOrder(), restAuthDomains.size());
            }

            final HTTPAuthenticator httpAuthenticator = authDomain.getHttpAuthenticator();

            if(authDomain.isChallenge() && firstChallengingHttpAuthenticator == null) {
                firstChallengingHttpAuthenticator = httpAuthenticator;
            }

            if(log.isTraceEnabled()) {
                log.trace("Try to extract auth creds from {} http authenticator", httpAuthenticator.getType());
            }
            final AuthCredentials ac;
            try {
                ac = httpAuthenticator.extractCredentials(request, threadContext);
            } catch (Exception e1) {
                if(log.isDebugEnabled()) {
                    log.debug("'{}' extracting credentials from {} http authenticator", e1.toString(), httpAuthenticator.getType(), e1);
                }
                continue;
            }
            authCredenetials = ac;

            if (ac == null) {
                //no credentials found in request
                if(anonymousAuthEnabled) {
                    continue;
                }

                if(authDomain.isChallenge() && httpAuthenticator.reRequestAuthentication(channel, null)) {
                    auditLog.logFailedLogin("<NONE>", false, null, request);
                    log.trace("No 'Authorization' header, send 401 and 'WWW-Authenticate Basic'");
                    return false;
                } else {
                    //no reRequest possible
                	log.trace("No 'Authorization' header, send 403");
                    continue;
                }
            } else {
                org.apache.logging.log4j.ThreadContext.put("user", ac.getUsername());
                if (!ac.isComplete()) {
                    //credentials found in request but we need another client challenge
                    if(httpAuthenticator.reRequestAuthentication(channel, ac)) {
                        //auditLog.logFailedLogin(ac.getUsername()+" <incomplete>", request); --noauditlog
                        return false;
                    } else {
                        //no reRequest possible
                        continue;
                    }

                }
            }

            //http completed       
            authenticatedUser = authcz(userCache, restRoleCache, ac, authDomain.getBackend(), restAuthorizers);

            if(authenticatedUser == null) {
                if(log.isDebugEnabled()) {
                    log.debug("Cannot authenticate rest user {} (or add roles) with authdomain {}/{} of {}, try next", ac.getUsername(), authDomain.getBackend().getType(), authDomain.getOrder(), restAuthDomains);
                }
                continue;
            }

            if(adminDns.isAdmin(authenticatedUser)) {
                log.error("Cannot authenticate rest user because admin user is not permitted to login via HTTP");
                auditLog.logFailedLogin(authenticatedUser.getName(), true, null, request);
                channel.sendResponse(new BytesRestResponse(RestStatus.FORBIDDEN, "Cannot authenticate user because admin user is not permitted to login via HTTP"));
                return false;
            }

            final String tenant = Utils.coalesce(request.header("sgtenant"), request.header("sg_tenant"));

            if(log.isDebugEnabled()) {
                log.debug("Rest user '{}' is authenticated", authenticatedUser);
                log.debug("sgtenant '{}'", tenant);
            }

            authenticatedUser.setRequestedTenant(tenant);
            authenticated = true;
            break;
        }//end looping auth domains


        if(authenticated) {
            final User impersonatedUser = impersonate(request, authenticatedUser);
            threadContext.putTransient(ConfigConstants.SG_USER, impersonatedUser==null?authenticatedUser:impersonatedUser);
            auditLog.logSucceededLogin((impersonatedUser==null?authenticatedUser:impersonatedUser).getName(), false, authenticatedUser.getName(), request);
        } else {
            if(log.isDebugEnabled()) {
                log.debug("User still not authenticated after checking {} auth domains", restAuthDomains.size());
            }

            if(authCredenetials == null && anonymousAuthEnabled) {
            	threadContext.putTransient(ConfigConstants.SG_USER, User.ANONYMOUS);
            	auditLog.logSucceededLogin(User.ANONYMOUS.getName(), false, null, request);
                if(log.isDebugEnabled()) {
                    log.debug("Anonymous User is authenticated");
                }
                return true;
            }

            if(firstChallengingHttpAuthenticator != null) {

                if(log.isDebugEnabled()) {
                    log.debug("Rerequest with {}", firstChallengingHttpAuthenticator.getClass());
                }

                if(firstChallengingHttpAuthenticator.reRequestAuthentication(channel, null)) {
                    if(log.isDebugEnabled()) {
                        log.debug("Rerequest {} failed", firstChallengingHttpAuthenticator.getClass());
                    }

                    log.warn("Authentication finally failed for {} from {}", authCredenetials == null ? null:authCredenetials.getUsername(), remoteAddress);
                    auditLog.logFailedLogin(authCredenetials == null ? null:authCredenetials.getUsername(), false, null, request);
                    return false;
                }
            }

            log.warn("Authentication finally failed for {} from {}", authCredenetials == null ? null:authCredenetials.getUsername(), remoteAddress);
            auditLog.logFailedLogin(authCredenetials == null ? null:authCredenetials.getUsername(), false, null, request);
            channel.sendResponse(new BytesRestResponse(RestStatus.UNAUTHORIZED, "Authentication finally failed"));
            return false;
        }

        return authenticated;
    }

    /**
     * no auditlog, throw no exception, does also authz for all authorizers
     *
     * @param cache
     * @param ac
     * @param authDomain
     * @return null if user cannot b authenticated
     */
    private User checkExistsAndAuthz(final Cache<String, User> cache, final User user, final AuthenticationBackend authenticationBackend, final Set<AuthorizationBackend> authorizers) {
        if(user == null) {
            return null;
        }

        try {
            return cache.get(user.getName(), new Callable<User>() { //no cache miss in case of noop
                @Override
                public User call() throws Exception {
                    if(log.isTraceEnabled()) {
                        log.trace("Credentials for user "+user.getName()+" not cached, return from "+authenticationBackend.getType()+" backend directly");
                    }
                    if(authenticationBackend.exists(user)) {
                        authz(user, null, authorizers); //no role cache because no miss here in case of noop
                        return user;
                    }

                    if(log.isDebugEnabled()) {
                        log.debug("User "+user.getName()+" does not exist in "+authenticationBackend.getType());
                    }
                    return null;
                }
            });
        } catch (Exception e) {
            if(log.isDebugEnabled()) {
                log.debug("Can not check and authorize "+user.getName()+" due to "+e.toString(), e);
            }
            return null;
        }
    }
    
    
    private void authz(User authenticatedUser, Cache<User, Set<String>> roleCache, final Set<AuthorizationBackend> authorizers) {
        
        if(authenticatedUser == null) {
            return;
        }
        
        if(roleCache != null) {

            final Set<String> cachedBackendRoles = roleCache.getIfPresent(authenticatedUser);
            
            if(cachedBackendRoles != null) {
                authenticatedUser.addRoles(new HashSet<String>(cachedBackendRoles));
                return;
            }
        }
        
        if(authorizers == null || authorizers.isEmpty()) {
            return;
        }
        
        for (final AuthorizationBackend ab : authorizers) {
            try {
                if(log.isTraceEnabled()) {
                    log.trace("Backend roles for "+authenticatedUser.getName()+" not cached, return from "+ab.getType()+" backend directly");
                }
                ab.fillRoles(authenticatedUser, new AuthCredentials(authenticatedUser.getName()));
            } catch (Exception e) {
                log.error("Cannot retrieve roles for {} from {} due to {}", authenticatedUser, ab.getType(), e.toString(), e);
            }
        }
        
        if(roleCache != null) {
             roleCache.put(authenticatedUser, new HashSet<String>(authenticatedUser.getRoles()));
        }
    }
    
    
    /**
     * no auditlog, throw no exception, does also authz for all authorizers
     *
     * @param cache
     * @param ac
     * @param authDomain
     * @return null if user cannot b authenticated
     */
    private User authcz(final Cache<AuthCredentials, User> cache, Cache<User, Set<String>> roleCache, final AuthCredentials ac, final AuthenticationBackend authBackend, final Set<AuthorizationBackend> authorizers) {
        if(ac == null) {
            return null;
        }
        try {
            
            //noop backend configured and no authorizers
            //that mean authc and authz was completely done via HTTP (like JWT or PKI)
            if(authBackend.getClass() == NoOpAuthenticationBackend.class && authorizers.isEmpty()) {
                //no cache
                return authBackend.authenticate(ac);
            }
        

        
            return cache.get(ac, new Callable<User>() {
                @Override
                public User call() throws Exception {
                    if(log.isTraceEnabled()) {
                        log.trace("Credentials for user "+ac.getUsername()+" not cached, return from "+authBackend.getType()+" backend directly");
                    }
                    final User authenticatedUser = authBackend.authenticate(ac);
                    authz(authenticatedUser, roleCache, authorizers);

                    return authenticatedUser;
                }
            });
        } catch (Exception e) {
            if(log.isDebugEnabled()) {
                log.debug("Can not authenticate "+ac.getUsername()+" due to "+e.toString(), e);
            }
            return null;
        } finally {
            ac.clearSecrets();
        }
    }

    private User impersonate(final TransportRequest tr, final User origPKIuser) throws ElasticsearchSecurityException {

        final String impersonatedUser = threadPool.getThreadContext().getHeader("sg_impersonate_as");

        if(Strings.isNullOrEmpty(impersonatedUser)) {
            return null; //nothing to do
        }

        if (!isInitialized()) {
            throw new ElasticsearchSecurityException("Could not check for impersonation because Search Guard is not yet initialized");
        }

        if (origPKIuser == null) {
            throw new ElasticsearchSecurityException("no original PKI user found");
        }

        User aU = origPKIuser;

        if (adminDns.isAdminDN(impersonatedUser)) {
            throw new ElasticsearchSecurityException("'"+origPKIuser.getName() + "' is not allowed to impersonate as an adminuser  '" + impersonatedUser+"'");
        }

        try {
            if (impersonatedUser != null && !adminDns.isTransportImpersonationAllowed(new LdapName(origPKIuser.getName()), impersonatedUser)) {
                throw new ElasticsearchSecurityException("'"+origPKIuser.getName() + "' is not allowed to impersonate as '" + impersonatedUser+"'");
            } else if (impersonatedUser != null) {
                aU = new User(impersonatedUser);
                if(log.isDebugEnabled()) {
                    log.debug("Impersonate from '{}' to '{}'",origPKIuser.getName(), impersonatedUser);
                }
            }
        } catch (final InvalidNameException e1) {
            throw new ElasticsearchSecurityException("PKI does not have a valid name ('" + origPKIuser.getName() + "'), should never happen",
                    e1);
        }

        return aU;
    }

    private User impersonate(final RestRequest request, final User originalUser) throws ElasticsearchSecurityException {

        final String impersonatedUserHeader = request.header("sg_impersonate_as");

        if (Strings.isNullOrEmpty(impersonatedUserHeader) || originalUser == null) {
            return null; // nothing to do
        }

        if (!isInitialized()) {
            throw new ElasticsearchSecurityException("Could not check for impersonation because Search Guard is not yet initialized");
        }

        if (adminDns.isAdminDN(impersonatedUserHeader)) {
            throw new ElasticsearchSecurityException("It is not allowed to impersonate as an adminuser  '" + impersonatedUserHeader + "'",
                    RestStatus.FORBIDDEN);
        }

        if (!adminDns.isRestImpersonationAllowed(originalUser.getName(), impersonatedUserHeader)) {
            throw new ElasticsearchSecurityException("'" + originalUser.getName() + "' is not allowed to impersonate as '" + impersonatedUserHeader
                    + "'", RestStatus.FORBIDDEN);
        } else {
            //loop over all http/rest auth domains
            for (final AuthDomain authDomain: restAuthDomains) {
                final AuthenticationBackend authenticationBackend = authDomain.getBackend();
                final User impersonatedUser = checkExistsAndAuthz(restImpersonationCache, new User(impersonatedUserHeader), authenticationBackend, restAuthorizers);

                if(impersonatedUser == null) {
                    log.debug("Unable to impersonate rest user from '{}' to '{}' because the impersonated user does not exists in {}, try next ...", originalUser.getName(), impersonatedUserHeader, authenticationBackend.getType());
                    continue;
                }

                if (log.isDebugEnabled()) {
                    log.debug("Impersonate rest user from '{}' to '{}'", originalUser.getName(), impersonatedUserHeader);
                }
                return impersonatedUser;
            }

            log.debug("Unable to impersonate rest user from '{}' to '{}' because the impersonated user does not exists", originalUser.getName(), impersonatedUserHeader);
            throw new ElasticsearchSecurityException("No such user:" + impersonatedUserHeader, RestStatus.FORBIDDEN);
        }

    }
    
    private User resolveTransportUsernameAttribute(User pkiUser) {
    	//#547
        if(transportUsernameAttribute != null && !transportUsernameAttribute.isEmpty()) {
	    	try {
				final LdapName sslPrincipalAsLdapName = new LdapName(pkiUser.getName());
				for(final Rdn rdn: sslPrincipalAsLdapName.getRdns()) {
					if(rdn.getType().equals(transportUsernameAttribute)) {
						return new User((String) rdn.getValue());
					}
				}
			} catch (InvalidNameException e) {
				//cannot happen
			}
        }
        
        return pkiUser;
    }
}
