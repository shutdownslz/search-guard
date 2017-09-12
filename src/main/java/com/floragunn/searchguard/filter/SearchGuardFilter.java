/*
 * Copyright 2015 floragunn UG (haftungsbeschränkt)
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

package com.floragunn.searchguard.filter;

import java.util.Objects;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.bulk.BulkShardRequest;
import org.elasticsearch.action.support.ActionFilter;
import org.elasticsearch.action.support.ActionFilterChain;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;

import com.floragunn.searchguard.auditlog.AuditLog;
import com.floragunn.searchguard.configuration.AdminDNs;
import com.floragunn.searchguard.configuration.DlsFlsRequestValve;
import com.floragunn.searchguard.configuration.PrivilegesEvaluator;
import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.support.HeaderHelper;
import com.floragunn.searchguard.user.User;

public class SearchGuardFilter implements ActionFilter {

    protected final Logger log = LogManager.getLogger(this.getClass());
    private final PrivilegesEvaluator evalp;
    private final Settings settings;
    private final AdminDNs adminDns;
    private DlsFlsRequestValve dlsFlsValve;
    private final AuditLog auditLog;
    private final ThreadContext threadContext;
    
    public SearchGuardFilter(final Settings settings, final PrivilegesEvaluator evalp, final AdminDNs adminDns,
            DlsFlsRequestValve dlsFlsValve, AuditLog auditLog, ThreadPool threadPool) {
        this.settings = settings;
        this.evalp = evalp;
        this.adminDns = adminDns;
        this.dlsFlsValve = dlsFlsValve;
        this.auditLog = auditLog;
        this.threadContext = threadPool.getThreadContext();
    }

    @Override
    public int order() {
        return Integer.MIN_VALUE;
    }

    @Override
    public void apply(Task task, final String action, final ActionRequest request, final ActionListener listener, final ActionFilterChain chain) {
        
        if(threadContext.getTransient("_sg_origin") == null) {
            threadContext.putTransient("_sg_origin", "LOCAL");
        }
        
        final User user = threadContext.getTransient(ConfigConstants.SG_USER);
        
        try {

            //let admin and conf requests pass
            final boolean userIsAdmin = isUserAdmin(user, adminDns);
            final boolean conRequest = "true".equals(HeaderHelper.getSafeFromHeader(threadContext, ConfigConstants.SG_CONF_REQUEST_HEADER));
            
            if(userIsAdmin || conRequest){

                if(userIsAdmin && !conRequest) {
                    auditLog.logAuthenticatedRequest(request, action);
                }

                if(!dlsFlsValve.invoke(request, listener, threadContext)) {
                    return;
                }
                
                chain.proceed(task, action, request, listener);
                return;
            }
            
            //let internal and cluster monitor requests pass if 
            //is a inter cluster/trusted cluster requests or origin is LOCAL and remote address is null
            //TODO: but no a internal:transport/proxy which is used for cross cluster search
            if(
                    (action.startsWith("internal:") || action.startsWith("cluster:monitor") || action.startsWith("indices:monitor"))
                     // && !action.startsWith("internal:transport/proxy/")
                      && (HeaderHelper.isInterClusterRequest(threadContext) 
                              || HeaderHelper.isTrustedClusterRequest(threadContext)
                            || ("LOCAL".equals((String)threadContext.getTransient("_sg_origin")) 
                                    && request.remoteAddress() == null))) {
                
                
                //TODO check indices:monitor/*,cluster:admin/reroute,indices:admin/mapping/put

                chain.proceed(task, action, request, listener);
                return;
                
            }
            
            //let inter cluster requests without users pass as lonf they have no remote address
            //currently only for indices:monitor/stats
            /*if(user == null  && HeaderHelper.isInterClusterRequest(threadContext) && request.remoteAddress() == null) {
                //must not be a shard request
                assert !(request instanceof BulkShardRequest): "bulk shard request not allowed here";              
                chain.proceed(task, action, request, listener);
                return;
            }
            
            [2017-09-12T21:41:54,434][ERROR][c.f.s.f.SearchGuardFilter] No user found for indices:monitor/stats from null LOCAL {}*/
           
            
            if(user == null) {
                log.error("No user found for "+ action+" from "+request.remoteAddress()+" "+threadContext.getTransient("_sg_origin")+" "+threadContext.getHeaders());
                listener.onFailure(new ElasticsearchSecurityException("No user found for "+action, RestStatus.INTERNAL_SERVER_ERROR));
                return;
            }
      
            final PrivilegesEvaluator eval = evalp;

            if (!eval.isInitialized()) {
                log.error("Search Guard not initialized (SG11) for {}", action);
                listener.onFailure(new ElasticsearchSecurityException("Search Guard not initialized (SG11) for " 
                + action+". See https://github.com/floragunncom/search-guard-docs/blob/master/sgadmin.md", RestStatus.SERVICE_UNAVAILABLE));
                return;
            }

            if (log.isTraceEnabled()) {
                log.trace("Evaluate permissions for user: {}", user.getName());
            }

            if (eval.evaluate(user, action, request)) {
                auditLog.logAuthenticatedRequest(request, action);
                if(!dlsFlsValve.invoke(request, listener, threadContext)) {
                    return;
                }
                chain.proceed(task, action, request, listener);
                return;
            } else {
                auditLog.logMissingPrivileges(action, request);
                log.debug("no permissions for {}", action);
                listener.onFailure(new ElasticsearchSecurityException("no permissions for " + action, RestStatus.FORBIDDEN));
                return;
            }
            
            
        } catch (Exception e) {
            log.error("Unexpected exception "+e, e);
            listener.onFailure(new ElasticsearchSecurityException("Unexpected exception " + action, RestStatus.INTERNAL_SERVER_ERROR));
            return;
        }
    }
    
    private static boolean isUserAdmin(User user, final AdminDNs adminDns) {
        if (user != null && adminDns.isAdmin(user.getName())) {
            return true;
        }

        return false;
    }

}
