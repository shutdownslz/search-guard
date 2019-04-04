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

package com.floragunn.searchguard.privileges;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.admin.cluster.shards.ClusterSearchShardsRequest;
import org.elasticsearch.action.admin.cluster.snapshots.restore.RestoreSnapshotRequest;
import org.elasticsearch.action.admin.indices.alias.IndicesAliasesAction;
import org.elasticsearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.elasticsearch.action.admin.indices.alias.IndicesAliasesRequest.AliasActions;
import org.elasticsearch.action.admin.indices.create.CreateIndexRequest;
import org.elasticsearch.action.admin.indices.delete.DeleteIndexAction;
import org.elasticsearch.action.bulk.BulkAction;
import org.elasticsearch.action.bulk.BulkItemRequest;
import org.elasticsearch.action.bulk.BulkShardRequest;
import org.elasticsearch.action.delete.DeleteAction;
import org.elasticsearch.action.get.MultiGetAction;
import org.elasticsearch.action.index.IndexAction;
import org.elasticsearch.action.search.MultiSearchAction;
import org.elasticsearch.action.search.SearchAction;
import org.elasticsearch.action.search.SearchScrollAction;
import org.elasticsearch.action.termvectors.MultiTermVectorsAction;
import org.elasticsearch.action.update.UpdateAction;
import org.elasticsearch.cluster.metadata.AliasMetaData;
import org.elasticsearch.cluster.metadata.IndexMetaData;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.collect.ImmutableOpenMap;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.index.reindex.ReindexAction;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;

import com.floragunn.searchguard.auditlog.AuditLog;
import com.floragunn.searchguard.configuration.ActionGroupHolder;
import com.floragunn.searchguard.configuration.ClusterInfoHolder;
import com.floragunn.searchguard.configuration.ConfigurationChangeListener;
import com.floragunn.searchguard.configuration.ConfigurationRepository;
import com.floragunn.searchguard.resolver.IndexResolverReplacer;
import com.floragunn.searchguard.resolver.IndexResolverReplacer.Resolved;
import com.floragunn.searchguard.sgconf.ConfigModel;
import com.floragunn.searchguard.sgconf.ConfigModel.SgRoles;
import com.floragunn.searchguard.sgconf.impl.CType;
import com.floragunn.searchguard.sgconf.impl.SgDynamicConfiguration;
import com.floragunn.searchguard.sgconf.impl.v6.Config;
import com.floragunn.searchguard.sgconf.impl.v6.Role;
import com.floragunn.searchguard.sgconf.impl.v6.RoleMappings;
import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.support.WildcardMatcher;
import com.floragunn.searchguard.user.User;
import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.ListMultimap;
import com.google.common.collect.MultimapBuilder.SetMultimapBuilder;
import com.google.common.collect.SetMultimap;

public class PrivilegesEvaluator implements ConfigurationChangeListener {

    protected final Logger log = LogManager.getLogger(this.getClass());
    protected final Logger actionTrace = LogManager.getLogger("sg_action_trace");
    private final ClusterService clusterService;

    private final IndexNameExpressionResolver resolver;

    private final AuditLog auditLog;
    private ThreadContext threadContext;
    private final ConfigurationRepository configurationRepository;

    private PrivilegesInterceptor privilegesInterceptor;

    private final boolean checkSnapshotRestoreWritePrivileges;

    private ConfigConstants.RolesMappingResolution rolesMappingResolution;

    private final ClusterInfoHolder clusterInfoHolder;
    //private final boolean typeSecurityDisabled = false;
    private final ConfigModel configModel;
    private final IndexResolverReplacer irr;
    private final SnapshotRestoreEvaluator snapshotRestoreEvaluator;
    private final SearchGuardIndexAccessEvaluator sgIndexAccessEvaluator;
    private final TermsAggregationEvaluator termsAggregationEvaluator;
    private final DlsFlsEvaluator dlsFlsEvaluator;
    private RoleMappingHolder roleMappingHolder = null;
    private TenantHolder tenantHolder = null;
    private final boolean enterpriseModulesEnabled;

    public PrivilegesEvaluator(final ClusterService clusterService, final ThreadPool threadPool,
            final ConfigurationRepository configurationRepository, final ActionGroupHolder ah, final IndexNameExpressionResolver resolver,
            AuditLog auditLog, final Settings settings, final PrivilegesInterceptor privilegesInterceptor, final ClusterInfoHolder clusterInfoHolder,
            final IndexResolverReplacer irr, boolean enterpriseModulesEnabled) {

        super();
        this.configurationRepository = configurationRepository;
        this.clusterService = clusterService;
        this.resolver = resolver;
        this.auditLog = auditLog;

        this.threadContext = threadPool.getThreadContext();
        this.privilegesInterceptor = privilegesInterceptor;

        try {
            rolesMappingResolution = ConfigConstants.RolesMappingResolution.valueOf(
                    settings.get(ConfigConstants.SEARCHGUARD_ROLES_MAPPING_RESOLUTION, ConfigConstants.RolesMappingResolution.MAPPING_ONLY.toString())
                            .toUpperCase());
        } catch (Exception e) {
            log.error("Cannot apply roles mapping resolution", e);
            rolesMappingResolution = ConfigConstants.RolesMappingResolution.MAPPING_ONLY;
        }

        this.checkSnapshotRestoreWritePrivileges = settings.getAsBoolean(ConfigConstants.SEARCHGUARD_CHECK_SNAPSHOT_RESTORE_WRITE_PRIVILEGES,
                ConfigConstants.SG_DEFAULT_CHECK_SNAPSHOT_RESTORE_WRITE_PRIVILEGES);

        this.clusterInfoHolder = clusterInfoHolder;
        //this.typeSecurityDisabled = settings.getAsBoolean(ConfigConstants.SEARCHGUARD_DISABLE_TYPE_SECURITY, false);
        configModel = new ConfigModel(ah);
        configurationRepository.subscribeOnChange(CType.ROLES, configModel);
        configurationRepository.subscribeOnChange(CType.ROLESMAPPING, this);
        this.irr = irr;
        snapshotRestoreEvaluator = new SnapshotRestoreEvaluator(settings, auditLog);
        sgIndexAccessEvaluator = new SearchGuardIndexAccessEvaluator(settings, auditLog);
        dlsFlsEvaluator = new DlsFlsEvaluator(settings, threadPool);
        termsAggregationEvaluator = new TermsAggregationEvaluator();
        tenantHolder = new TenantHolder();
        configurationRepository.subscribeOnChange(CType.ROLES, tenantHolder);
        this.enterpriseModulesEnabled = enterpriseModulesEnabled;
    }

    private SgDynamicConfiguration<Role> getRolesSettings() {
        return (SgDynamicConfiguration<Role>) configurationRepository.getConfiguration(CType.ROLES);
    }

    private class TenantHolder implements ConfigurationChangeListener {

        private SetMultimap<String, Tuple<String, Boolean>> tenantsMM = null;

        public Map<String, Boolean> mapTenants(final User user, Set<String> roles) {

            if (user == null || tenantsMM == null) {
                return Collections.emptyMap();
            }

            final Map<String, Boolean> result = new HashMap<>(roles.size());
            result.put(user.getName(), true);

            tenantsMM.entries().stream().filter(e -> roles.contains(e.getKey())).filter(e -> !user.getName().equals(e.getValue().v1())).forEach(e -> {
                final String tenant = e.getValue().v1();
                final boolean rw = e.getValue().v2();

                if (rw || !result.containsKey(tenant)) { //RW outperforms RO
                    result.put(tenant, rw);
                }
            });

            return Collections.unmodifiableMap(result);
        }

        @Override
        public void onChange(CType cType, SgDynamicConfiguration<?> configuration) {

            SgDynamicConfiguration<Role> roles = (SgDynamicConfiguration<Role>) configuration;
            final Set<Future<Tuple<String, Set<Tuple<String, Boolean>>>>> futures = new HashSet<>(configuration.getCEntries().size());

            final ExecutorService execs = Executors.newFixedThreadPool(10);

            for(Entry<String, Role> sgRole: roles.getCEntries().entrySet()) {
                
                if(sgRole.getValue() == null) {
                    continue;
                }

                Future<Tuple<String, Set<Tuple<String, Boolean>>>> future = execs.submit(new Callable<Tuple<String, Set<Tuple<String, Boolean>>>>() {
                    @Override
                    public Tuple<String, Set<Tuple<String, Boolean>>> call() throws Exception {
                        final Set<Tuple<String, Boolean>> tuples = new HashSet<>();
                        final Map<String, String> tenants = sgRole.getValue().getTenants();

                        if (tenants != null) {
                            
                            for (String tenant : tenants.keySet()) {

                                if ("RW".equalsIgnoreCase(tenants.get(tenant))) {
                                    //RW
                                    tuples.add(new Tuple<String, Boolean>(tenant, true));
                                } else {
                                    //RO
                                    //if(!tenantsMM.containsValue(value)) { //RW outperforms RO
                                    tuples.add(new Tuple<String, Boolean>(tenant, false));
                                    //}
                                }
                            }
                        }

                        return new Tuple<String, Set<Tuple<String, Boolean>>>(sgRole.getKey(), tuples);
                    }
                });

                futures.add(future);

            }

            execs.shutdown();
            try {
                execs.awaitTermination(30, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                log.error("Thread interrupted (1) while loading roles");
                return;
            }

            try {
                final SetMultimap<String, Tuple<String, Boolean>> tenantsMM_ = SetMultimapBuilder.hashKeys(futures.size()).hashSetValues(16).build();

                for (Future<Tuple<String, Set<Tuple<String, Boolean>>>> future : futures) {
                    Tuple<String, Set<Tuple<String, Boolean>>> result = future.get();
                    tenantsMM_.putAll(result.v1(), result.v2());
                }

                tenantsMM = tenantsMM_;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                log.error("Thread interrupted (2) while loading roles");
                return;
            } catch (ExecutionException e) {
                log.error("Error while updating roles: {}", e.getCause(), e.getCause());
                throw ExceptionsHelper.convertToElastic(e);
            }

        }
    }

    private class RoleMappingHolder {

        private ListMultimap<String, String> users;
        private ListMultimap<Set<String>, String> abars;
        private ListMultimap<String, String> bars;
        private ListMultimap<String, String> hosts;

        private RoleMappingHolder(SgDynamicConfiguration<RoleMappings> rolesMapping) {

            if (rolesMapping != null) {

                final ListMultimap<String, String> users_ = ArrayListMultimap.create();
                final ListMultimap<Set<String>, String> abars_ = ArrayListMultimap.create();
                final ListMultimap<String, String> bars_ = ArrayListMultimap.create();
                final ListMultimap<String, String> hosts_ = ArrayListMultimap.create();

                for (final Entry<String, RoleMappings> roleMap : rolesMapping.getCEntries().entrySet()) {

                    for (String u : roleMap.getValue().getUsers()) {
                        users_.put(u, roleMap.getKey());
                    }

                    final Set<String> abar = new HashSet<String>(roleMap.getValue().getAndBackendroles());

                    if (!abar.isEmpty()) {
                        abars_.put(abar, roleMap.getKey());
                    }

                    for (String bar : roleMap.getValue().getBackendroles()) {
                        bars_.put(bar, roleMap.getKey());
                    }

                    for (String host : roleMap.getValue().getHosts()) {
                        hosts_.put(host, roleMap.getKey());
                    }
                }

                users = users_;
                abars = abars_;
                bars = bars_;
                hosts = hosts_;
            }
        }

        private Set<String> map(final User user, final TransportAddress caller) {

            if (user == null || users == null || abars == null || bars == null || hosts == null) {
                return Collections.emptySet();
            }

            final Set<String> sgRoles = new TreeSet<String>();

            if (rolesMappingResolution == ConfigConstants.RolesMappingResolution.BOTH
                    || rolesMappingResolution == ConfigConstants.RolesMappingResolution.BACKENDROLES_ONLY) {
                if (log.isDebugEnabled()) {
                    log.debug("Pass backendroles from {}", user);
                }
                sgRoles.addAll(user.getRoles());
            }

            if (((rolesMappingResolution == ConfigConstants.RolesMappingResolution.BOTH
                    || rolesMappingResolution == ConfigConstants.RolesMappingResolution.MAPPING_ONLY))) {

                for (String p : WildcardMatcher.getAllMatchingPatterns(users.keySet(), user.getName())) {
                    sgRoles.addAll(users.get(p));
                }

                for (String p : WildcardMatcher.getAllMatchingPatterns(bars.keySet(), user.getRoles())) {
                    sgRoles.addAll(bars.get(p));
                }

                for (Set<String> p : abars.keySet()) {
                    if (WildcardMatcher.allPatternsMatched(p, user.getRoles())) {
                        sgRoles.addAll(abars.get(p));
                    }
                }

                if (caller != null) {
                    //IPV4 or IPv6 (compressed and without scope identifiers)
                    final String ipAddress = caller.getAddress();

                    for (String p : WildcardMatcher.getAllMatchingPatterns(hosts.keySet(), ipAddress)) {
                        sgRoles.addAll(hosts.get(p));
                    }

                    final String hostResolverMode = getConfigSettings().dynamic.hosts_resolver_mode;

                    if (caller.address() != null
                            && (hostResolverMode.equalsIgnoreCase("ip-hostname") || hostResolverMode.equalsIgnoreCase("ip-hostname-lookup"))) {
                        final String hostName = caller.address().getHostString();

                        for (String p : WildcardMatcher.getAllMatchingPatterns(hosts.keySet(), hostName)) {
                            sgRoles.addAll(hosts.get(p));
                        }
                    }

                    if (caller.address() != null && hostResolverMode.equalsIgnoreCase("ip-hostname-lookup")) {

                        final String resolvedHostName = caller.address().getHostName();

                        for (String p : WildcardMatcher.getAllMatchingPatterns(hosts.keySet(), resolvedHostName)) {
                            sgRoles.addAll(hosts.get(p));
                        }
                    }
                }
            }

            return Collections.unmodifiableSet(sgRoles);

        }
    }

    @Override
    public void onChange(CType cType, SgDynamicConfiguration<?> configuration) {
        final RoleMappingHolder tmp = new RoleMappingHolder((SgDynamicConfiguration<RoleMappings>) configuration);
        this.roleMappingHolder = tmp;
    }

    private Config getConfigSettings() {
        return CType.getConfig(configurationRepository.getConfiguration(CType.CONFIG));
    }

    private SgRoles getSgRoles(Set<String> roles) {
        return configModel.getSgRoles().filter(roles);
    }

    public boolean isInitialized() {
        return roleMappingHolder != null && configModel.getSgRoles() != null && getRolesSettings() != null && getConfigSettings() != null;
    }

    public PrivilegesEvaluatorResponse evaluate(final User user, String action0, final ActionRequest request, Task task) {

        if (!isInitialized()) {
            throw new ElasticsearchSecurityException("Search Guard is not initialized.");
        }

        if (action0.startsWith("internal:indices/admin/upgrade")) {
            action0 = "indices:admin/upgrade";
        }

        final TransportAddress caller = Objects.requireNonNull((TransportAddress) this.threadContext.getTransient(ConfigConstants.SG_REMOTE_ADDRESS));

        final Set<String> mappedRoles = mapSgRoles(user, caller);
        final SgRoles sgRoles = getSgRoles(mappedRoles);

        final PrivilegesEvaluatorResponse presponse = new PrivilegesEvaluatorResponse();

        if (log.isDebugEnabled()) {
            log.debug("### evaluate permissions for {} on {}", user, clusterService.localNode().getName());
            log.debug("action: " + action0 + " (" + request.getClass().getSimpleName() + ")");
        }

        final Resolved requestedResolved = irr.resolveRequest(request);

        if (log.isDebugEnabled()) {
            log.debug("requestedResolved : {}", requestedResolved);
        }

        // check dlsfls 
        if (enterpriseModulesEnabled
                //&& (action0.startsWith("indices:data/read") || action0.equals(ClusterSearchShardsAction.NAME))
                && dlsFlsEvaluator.evaluate(request, clusterService, resolver, requestedResolved, user, sgRoles, presponse).isComplete()) {
            return presponse;
        }

        // check snapshot/restore requests 
        if (snapshotRestoreEvaluator.evaluate(request, task, action0, clusterInfoHolder, presponse).isComplete()) {
            return presponse;
        }

        // SG index access
        if (sgIndexAccessEvaluator.evaluate(request, task, action0, requestedResolved, presponse).isComplete()) {
            return presponse;
        }

        final boolean dnfofEnabled =
                getConfigSettings().dynamic.kibana.do_not_fail_on_forbidden
                || getConfigSettings().dynamic.do_not_fail_on_forbidden;
        
        if(log.isTraceEnabled()) {
            log.trace("dnfof enabled? {}", dnfofEnabled);
        }
        
        final Config config = getConfigSettings();
        
        if (isClusterPerm(action0)) {
            if (!sgRoles.impliesClusterPermissionPermission(action0)) {
                presponse.missingPrivileges.add(action0);
                presponse.allowed = false;
                log.info("No {}-level perm match for {} {} [Action [{}]] [RolesChecked {}]", "cluster", user, requestedResolved, action0,
                        sgRoles.getRoles().stream().map(r -> r.getName()).toArray());
                log.info("No permissions for {}", presponse.missingPrivileges);
                return presponse;
            } else {

                if (request instanceof RestoreSnapshotRequest && checkSnapshotRestoreWritePrivileges) {
                    if (log.isDebugEnabled()) {
                        log.debug("Normally allowed but we need to apply some extra checks for a restore request.");
                    }
                } else {

                    if (privilegesInterceptor.getClass() != PrivilegesInterceptor.class) {

                        final Boolean replaceResult = privilegesInterceptor.replaceKibanaIndex(request, action0, user, config, requestedResolved,
                                mapTenants(user, mappedRoles));

                        if (log.isDebugEnabled()) {
                            log.debug("Result from privileges interceptor for cluster perm: {}", replaceResult);
                        }

                        if (replaceResult == Boolean.TRUE) {
                            auditLog.logMissingPrivileges(action0, request, task);
                            return presponse;
                        }

                        if (replaceResult == Boolean.FALSE) {
                            presponse.allowed = true;
                            return presponse;
                        }
                    }

                    if (dnfofEnabled && (action0.startsWith("indices:data/read/")) && !requestedResolved.getAllIndices().isEmpty()) {

                        if (requestedResolved.getAllIndices().isEmpty()) {
                            presponse.missingPrivileges.clear();
                            presponse.allowed = true;
                            return presponse;
                        }

                        Set<String> reduced = sgRoles.reduce(requestedResolved, user, new String[] { action0 }, resolver, clusterService);

                        if (reduced.isEmpty()) {
                            presponse.allowed = false;
                            return presponse;
                        }

                        if (irr.replace(request, true, reduced.toArray(new String[0]))) {
                            presponse.missingPrivileges.clear();
                            presponse.allowed = true;
                            return presponse;
                        }
                    }

                    if (log.isDebugEnabled()) {
                        log.debug("Allowed because we have cluster permissions for " + action0);
                    }
                    presponse.allowed = true;
                    return presponse;
                }

            }
        }

        // term aggregations
        if (termsAggregationEvaluator.evaluate(request, clusterService, user, sgRoles, resolver, presponse).isComplete()) {
            return presponse;
        }

        final Set<String> allIndexPermsRequired = evaluateAdditionalIndexPermissions(request, action0);
        final String[] allIndexPermsRequiredA = allIndexPermsRequired.toArray(new String[0]);

        if (log.isDebugEnabled()) {
            log.debug("requested {} from {}", allIndexPermsRequired, caller);
        }

        presponse.missingPrivileges.clear();
        presponse.missingPrivileges.addAll(allIndexPermsRequired);

        if (log.isDebugEnabled()) {
            log.debug("requested resolved indextypes: {}", requestedResolved);
        }

        if (log.isDebugEnabled()) {
            log.debug("sgr: {}", sgRoles.getRoles().stream().map(d -> d.getName()).collect(Collectors.toList()));
        }

        //TODO exclude sg index

        if (privilegesInterceptor.getClass() != PrivilegesInterceptor.class) {

            final Boolean replaceResult = privilegesInterceptor.replaceKibanaIndex(request, action0, user, config, requestedResolved,
                    mapTenants(user, mappedRoles));

            if (log.isDebugEnabled()) {
                log.debug("Result from privileges interceptor: {}", replaceResult);
            }

            if (replaceResult == Boolean.TRUE) {
                auditLog.logMissingPrivileges(action0, request, task);
                return presponse;
            }

            if (replaceResult == Boolean.FALSE) {
                presponse.allowed = true;
                return presponse;
            }
        }

        if (dnfofEnabled && (action0.startsWith("indices:data/read/") || action0.startsWith("indices:admin/mappings/fields/get")
                || action0.equals("indices:admin/shards/search_shards"))) {

            if (requestedResolved.getAllIndices().isEmpty()) {
                presponse.missingPrivileges.clear();
                presponse.allowed = true;
                return presponse;
            }

            Set<String> reduced = sgRoles.reduce(requestedResolved, user, allIndexPermsRequiredA, resolver, clusterService);

            if (reduced.isEmpty()) {
                presponse.allowed = false;
                return presponse;
            }

            if (irr.replace(request, true, reduced.toArray(new String[0]))) {
                presponse.missingPrivileges.clear();
                presponse.allowed = true;
                return presponse;
            }
        }

        //not bulk, mget, etc request here
        boolean permGiven = false;
        
        if (log.isDebugEnabled()) {
            log.debug("sgr2: {}", sgRoles.getRoles().stream().map(d -> d.getName()).collect(Collectors.toList()));
        }

        if (config.dynamic.multi_rolespan_enabled) {
            permGiven = sgRoles.impliesTypePermGlobal(requestedResolved, user, allIndexPermsRequiredA, resolver, clusterService);
        } else {
            permGiven = sgRoles.get(requestedResolved, user, allIndexPermsRequiredA, resolver, clusterService);

        }

        if (!permGiven) {
            log.info("No {}-level perm match for {} {} [Action [{}]] [RolesChecked {}]", "index", user, requestedResolved, action0,
                    sgRoles.getRoles().stream().map(r -> r.getName()).toArray());
            log.info("No permissions for {}", presponse.missingPrivileges);
        } else {

            if (checkFilteredAliases(requestedResolved.getAllIndices(), action0)) {
                presponse.allowed = false;
                return presponse;
            }

            if (log.isDebugEnabled()) {
                log.debug("Allowed because we have all indices permissions for " + action0);
            }
        }

        presponse.allowed = permGiven;
        return presponse;

    }


//        final SgDynamicConfiguration<RoleMappings> rolesMapping = getRolesMappingSettings();
//        final Set<String> sgRoles = new TreeSet<String>();

    public Set<String> mapSgRoles(final User user, final TransportAddress caller) {
        return this.roleMappingHolder.map(user, caller);
    }


    /*public Set<String> mapSgRoles__old(final User user, final TransportAddress caller) {
    
        if(user == null) {
            return Collections.emptySet();
        }
    
        final Settings rolesMapping = configurationRepository.getConfiguration(ConfigConstants.CONFIGNAME_ROLES_MAPPING);
        final Set<String> sgRoles = new TreeSet<String>();
        final String[] userRoles = user.getRoles().toArray(new String[0]);
    
        if(rolesMappingResolution == ConfigConstants.RolesMappingResolution.BOTH
                || rolesMappingResolution == ConfigConstants.RolesMappingResolution.BACKENDROLES_ONLY) {
            if(log.isDebugEnabled()) {
                log.debug("Pass backendroles from {}", user);
            }
            sgRoles.addAll(user.getRoles());
        }
        
    
        if(rolesMapping != null && ((rolesMappingResolution == ConfigConstants.RolesMappingResolution.BOTH
                || rolesMappingResolution == ConfigConstants.RolesMappingResolution.MAPPING_ONLY))) {
<<<<<<< HEAD
            for (final Entry<String, RoleMappings> roleMap : rolesMapping.getCEntries().entrySet()) {
                //final DynamicConfiguration roleMapSettings = rolesMapping.getByPrefix(DotPath.of(roleMap));

                if (WildcardMatcher.allPatternsMatched(roleMap.getValue().getAndBackendroles().toArray(new String[0]), user.getRoles().toArray(new String[0]))) {
                    sgRoles.add(roleMap.getKey());
                    continue;
                }

                if (WildcardMatcher.matchAny(roleMap.getValue().getBackendroles().toArray(new String[0]), user.getRoles().toArray(new String[0]))) {
                    sgRoles.add(roleMap.getKey());
                    continue;
                }

                if (WildcardMatcher.matchAny(roleMap.getValue().getUsers(), user.getName())) {
                    sgRoles.add(roleMap.getKey());
=======
            for (final String roleMap : rolesMapping.names()) {
                
                final Settings roleMapSettings = rolesMapping.getByPrefix(roleMap);
    
                if (WildcardMatcher.allPatternsMatched(roleMapSettings.getAsList(".and_backendroles", Collections.emptyList()).toArray(new String[0]), userRoles)) {
                    sgRoles.add(roleMap);
                    continue;
                }
    
                if (WildcardMatcher.matchAny(roleMapSettings.getAsList(".backendroles", Collections.emptyList()).toArray(new String[0]), userRoles)) {
                    sgRoles.add(roleMap);
                    continue;
                }
    
                if (WildcardMatcher.matchAny(roleMapSettings.getAsList(".users"), user.getName())) {
                    sgRoles.add(roleMap);
>>>>>>> master
                    continue;
                }
                
                if(caller != null && log.isTraceEnabled()) {
                    log.trace("caller (getAddress()) is {}", caller.getAddress());
                    log.trace("caller unresolved? {}", caller.address().isUnresolved());
                    log.trace("caller inner? {}", caller.address().getAddress()==null?"<unresolved>":caller.address().getAddress().toString());
                    log.trace("caller (getHostString()) is {}", caller.address().getHostString());
                    log.trace("caller (getHostName(), dns) is {}", caller.address().getHostName()); //reverse lookup
                }
                
                if(caller != null) {
                    //IPV4 or IPv6 (compressed and without scope identifiers)
                    final String ipAddress = caller.getAddress();
                    if (WildcardMatcher.matchAny(roleMap.getValue().getHosts(), ipAddress)) {
                        sgRoles.add(roleMap.getKey());
                        continue;
                    }
    
                    final String hostResolverMode = getConfigSettings().dynamic.hosts_resolver_mode;
                    
                    if(caller.address() != null && (hostResolverMode.equalsIgnoreCase("ip-hostname") || hostResolverMode.equalsIgnoreCase("ip-hostname-lookup"))){
                        final String hostName = caller.address().getHostString();
        
                        if (WildcardMatcher.matchAny(roleMap.getValue().getHosts(), hostName)) {
                            sgRoles.add(roleMap.getKey());
                            continue;
                        }
                    }
                    
                    if(caller.address() != null && hostResolverMode.equalsIgnoreCase("ip-hostname-lookup")){
    
                        final String resolvedHostName = caller.address().getHostName();
             
                        if (WildcardMatcher.matchAny(roleMap.getValue().getHosts(), resolvedHostName)) {
                            sgRoles.add(roleMap.getKey());
                            continue;
                        }
                    }
                }
                
                
            }
        }
        
        
    
        return Collections.unmodifiableSet(sgRoles);
    
    }*/

    public Map<String, Boolean> mapTenants(final User user, Set<String> roles) {
        return this.tenantHolder.mapTenants(user, roles);
    }

    /*public Map<String, Boolean> mapTenants00(final User user, Set<String> roles) {
    
        
        if(user == null) {
            return Collections.emptyMap();
        }
    
        final Map<String, Boolean> result = new HashMap<>();
        result.put(user.getName(), true);
<<<<<<< HEAD

        for(String sgRole: mapSgRoles(user, caller)) {
            Role role = getRolesSettings().getCEntry(sgRole);
           

            if(role != null) {
                
                for(Entry<String, String> tenant: role.getTenants().entrySet()) {

                    if(tenant.getKey().equals(user.getName())) {
                        continue;
                    }

                    if("RW".equalsIgnoreCase(tenant.getValue())) {
                        result.put(tenant.getKey(), true);
=======
    
        for(String sgRole: roles) {
            Settings tenants = getRolesSettings().getByPrefix(sgRole+".tenants.");
    
            if(tenants != null) {
                for(String tenant: tenants.names()) {
    
                    if(tenant.equals(user.getName())) {
                        continue;
                    }
    
                    if("RW".equalsIgnoreCase(tenants.get(tenant, "RO"))) {
                        result.put(tenant, true);
>>>>>>> master
                    } else {
                        if(!result.containsKey(tenant.getKey())) { //RW outperforms RO
                            result.put(tenant.getKey(), false);
                        }
                    }
                }
            }
    
        }
    
        return Collections.unmodifiableMap(result);
    }*/

    public Set<String> getAllConfiguredTenantNames() {
//<<<<<<< HEAD
    	
    	final Set<String> configuredTenants = new HashSet<>();
    	for(Entry<String, Role> sgRole: getRolesSettings().getCEntries().entrySet()) {
    	    Map<String, String> tenants = sgRole.getValue().getTenants();

            if(tenants != null) {
                configuredTenants.addAll(tenants.keySet());
/*=======

        final Settings roles = getRolesSettings();

        if (roles == null || roles.isEmpty()) {
            return Collections.emptySet();
        }

        final Set<String> configuredTenants = new HashSet<>();
        for (String sgRole : roles.names()) {
            Settings tenants = roles.getByPrefix(sgRole + ".tenants.");

            if (tenants != null) {
                configuredTenants.addAll(tenants.names());
>>>>>>> master*/
            }

        }

        return Collections.unmodifiableSet(configuredTenants);
    }

    public boolean multitenancyEnabled() {
        return privilegesInterceptor.getClass() != PrivilegesInterceptor.class
                && getConfigSettings().dynamic.kibana.multitenancy_enabled;
    }

    public boolean notFailOnForbiddenEnabled() {
        return privilegesInterceptor.getClass() != PrivilegesInterceptor.class
                && getConfigSettings().dynamic.kibana.do_not_fail_on_forbidden;
    }

    public String kibanaIndex() {
        return getConfigSettings().dynamic.kibana.index;
    }

    public String kibanaServerUsername() {
        return getConfigSettings().dynamic.kibana.server_username;
    }

    private Set<String> evaluateAdditionalIndexPermissions(final ActionRequest request, final String originalAction) {
        //--- check inner bulk requests
        final Set<String> additionalPermissionsRequired = new HashSet<>();

        if (!isClusterPerm(originalAction)) {
            additionalPermissionsRequired.add(originalAction);
        }

        if (request instanceof ClusterSearchShardsRequest) {
            additionalPermissionsRequired.add(SearchAction.NAME);
        }

        if (request instanceof BulkShardRequest) {
            BulkShardRequest bsr = (BulkShardRequest) request;
            for (BulkItemRequest bir : bsr.items()) {
                switch (bir.request().opType()) {
                case CREATE:
                    additionalPermissionsRequired.add(IndexAction.NAME);
                    break;
                case INDEX:
                    additionalPermissionsRequired.add(IndexAction.NAME);
                    break;
                case DELETE:
                    additionalPermissionsRequired.add(DeleteAction.NAME);
                    break;
                case UPDATE:
                    additionalPermissionsRequired.add(UpdateAction.NAME);
                    break;
                }
            }
        }

        if (request instanceof IndicesAliasesRequest) {
            IndicesAliasesRequest bsr = (IndicesAliasesRequest) request;
            for (AliasActions bir : bsr.getAliasActions()) {
                switch (bir.actionType()) {
                case REMOVE_INDEX:
                    additionalPermissionsRequired.add(DeleteIndexAction.NAME);
                    break;
                default:
                    break;
                }
            }
        }

        if (request instanceof CreateIndexRequest) {
            CreateIndexRequest cir = (CreateIndexRequest) request;
            if (cir.aliases() != null && !cir.aliases().isEmpty()) {
                additionalPermissionsRequired.add(IndicesAliasesAction.NAME);
            }
        }

        if (request instanceof RestoreSnapshotRequest && checkSnapshotRestoreWritePrivileges) {
            additionalPermissionsRequired.addAll(ConfigConstants.SG_SNAPSHOT_RESTORE_NEEDED_WRITE_PRIVILEGES);
        }

        if (actionTrace.isTraceEnabled() && additionalPermissionsRequired.size() > 1) {
            actionTrace.trace(("Additional permissions required: " + additionalPermissionsRequired));
        }

        if (log.isDebugEnabled() && additionalPermissionsRequired.size() > 1) {
            log.debug("Additional permissions required: " + additionalPermissionsRequired);
        }

        return Collections.unmodifiableSet(additionalPermissionsRequired);
    }

    private static boolean isClusterPerm(String action0) {
        return (action0.startsWith("cluster:") || action0.startsWith("indices:admin/template/")

                || action0.startsWith(SearchScrollAction.NAME) || (action0.equals(BulkAction.NAME)) || (action0.equals(MultiGetAction.NAME))
                || (action0.equals(MultiSearchAction.NAME)) || (action0.equals(MultiTermVectorsAction.NAME)) || (action0.equals(ReindexAction.NAME))

        );
    }

    private boolean checkFilteredAliases(Set<String> requestedResolvedIndices, String action) {
        //check filtered aliases
        for (String requestAliasOrIndex : requestedResolvedIndices) {

            final List<AliasMetaData> filteredAliases = new ArrayList<AliasMetaData>();

            final IndexMetaData indexMetaData = clusterService.state().metaData().getIndices().get(requestAliasOrIndex);

            if (indexMetaData == null) {
                log.debug("{} does not exist in cluster metadata", requestAliasOrIndex);
                continue;
            }

            final ImmutableOpenMap<String, AliasMetaData> aliases = indexMetaData.getAliases();

            if (aliases != null && aliases.size() > 0) {

                if (log.isDebugEnabled()) {
                    log.debug("Aliases for {}: {}", requestAliasOrIndex, aliases);
                }

                final Iterator<String> it = aliases.keysIt();
                while (it.hasNext()) {
                    final String alias = it.next();
                    final AliasMetaData aliasMetaData = aliases.get(alias);

                    if (aliasMetaData != null && aliasMetaData.filteringRequired()) {
                        filteredAliases.add(aliasMetaData);
                        if (log.isDebugEnabled()) {
                            log.debug(alias + " is a filtered alias " + aliasMetaData.getFilter());
                        }
                    } else {
                        if (log.isDebugEnabled()) {
                            log.debug(alias + " is not an alias or does not have a filter");
                        }
                    }
                }
            }

            if (filteredAliases.size() > 1 && WildcardMatcher.match("indices:data/read/*search*", action)) {
                //TODO add queries as dls queries (works only if dls module is installed)
                final String faMode = getConfigSettings().dynamic.filtered_alias_mode;

                if (faMode.equals("warn")) {
                    log.warn("More than one ({}) filtered alias found for same index ({}). This is currently not recommended. Aliases: {}",
                            filteredAliases.size(), requestAliasOrIndex, toString(filteredAliases));
                } else if (faMode.equals("disallow")) {
                    log.error("More than one ({}) filtered alias found for same index ({}). This is currently not supported. Aliases: {}",
                            filteredAliases.size(), requestAliasOrIndex, toString(filteredAliases));
                    return true;
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("More than one ({}) filtered alias found for same index ({}). Aliases: {}", filteredAliases.size(),
                                requestAliasOrIndex, toString(filteredAliases));
                    }
                }
            }
        } //end-for

        return false;
    }

    private List<String> toString(List<AliasMetaData> aliases) {
        if (aliases == null || aliases.size() == 0) {
            return Collections.emptyList();
        }

        final List<String> ret = new ArrayList<>(aliases.size());

        for (final AliasMetaData amd : aliases) {
            if (amd != null) {
                ret.add(amd.alias());
            }
        }

        return Collections.unmodifiableList(ret);
    }

}
