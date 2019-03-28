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

package com.floragunn.searchguard.transport;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.admin.cluster.shards.ClusterSearchShardsAction;
import org.elasticsearch.action.admin.cluster.shards.ClusterSearchShardsResponse;
import org.elasticsearch.action.get.GetRequest;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.Transport.Connection;
import org.elasticsearch.transport.TransportException;
import org.elasticsearch.transport.TransportInterceptor.AsyncSender;
import org.elasticsearch.transport.TransportRequest;
import org.elasticsearch.transport.TransportRequestHandler;
import org.elasticsearch.transport.TransportRequestOptions;
import org.elasticsearch.transport.TransportResponse;
import org.elasticsearch.transport.TransportResponseHandler;

import com.floragunn.searchguard.SearchGuardPlugin;
import com.floragunn.searchguard.auditlog.AuditLog;
import com.floragunn.searchguard.auditlog.AuditLog.Origin;
import com.floragunn.searchguard.auth.BackendRegistry;
import com.floragunn.searchguard.configuration.ClusterInfoHolder;
import com.floragunn.searchguard.ssl.SslExceptionHandler;
import com.floragunn.searchguard.ssl.transport.PrincipalExtractor;
import com.floragunn.searchguard.support.Base64Helper;
import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.user.User;
import com.google.common.collect.Maps;

public class SearchGuardInterceptor {

    protected final Logger actionTrace = LogManager.getLogger("sg_action_trace");
    private BackendRegistry backendRegistry;
    private AuditLog auditLog;
    private final ThreadPool threadPool;
    private final PrincipalExtractor principalExtractor;
    private final InterClusterRequestEvaluator requestEvalProvider;
    private final ClusterService cs;
    private final Settings settings;
    private final SslExceptionHandler sslExceptionHandler;
    private final ClusterInfoHolder clusterInfoHolder;

    public SearchGuardInterceptor(final Settings settings,
            final ThreadPool threadPool, final BackendRegistry backendRegistry,
            final AuditLog auditLog, final PrincipalExtractor principalExtractor,
            final InterClusterRequestEvaluator requestEvalProvider,
            final ClusterService cs,
            final SslExceptionHandler sslExceptionHandler,
            final ClusterInfoHolder clusterInfoHolder) {
        this.backendRegistry = backendRegistry;
        this.auditLog = auditLog;
        this.threadPool = threadPool;
        this.principalExtractor = principalExtractor;
        this.requestEvalProvider = requestEvalProvider;
        this.cs = cs;
        this.settings = settings;
        this.sslExceptionHandler = sslExceptionHandler;
        this.clusterInfoHolder = clusterInfoHolder;
    }

    public <T extends TransportRequest> SearchGuardRequestHandler<T> getHandler(String action,
            TransportRequestHandler<T> actualHandler) {
        return new SearchGuardRequestHandler<T>(action, actualHandler, threadPool, backendRegistry, auditLog,
                principalExtractor, requestEvalProvider, cs, sslExceptionHandler);
    }

    public <T extends TransportResponse> void sendRequestDecorate(AsyncSender sender, Connection connection, String action,
            TransportRequest request, TransportRequestOptions options, TransportResponseHandler<T> handler) {
        
        final Map<String, String> origHeaders0 = getThreadContext().getHeaders();
        final User user0 = getThreadContext().getTransient(ConfigConstants.SG_USER);
        final String origin0 = getThreadContext().getTransient(ConfigConstants.SG_ORIGIN);
        final Object remoteAdress0 = getThreadContext().getTransient(ConfigConstants.SG_REMOTE_ADDRESS);
        final Map<String, List<String>> origResponseHeaders0 = getThreadContext().getResponseHeaders();

        //stash headers and transient objects
        try (ThreadContext.StoredContext stashedContext = getThreadContext().stashContext()) {
            
            final TransportResponseHandler<T> restoringHandler = new RestoringTransportResponseHandler<T>(handler, stashedContext);
            getThreadContext().putHeader("_sg_remotecn", cs.getClusterName().value());

            if(this.settings.get("tribe.name", null) == null
                    && settings.getByPrefix("tribe").size() > 0) {
                getThreadContext().putHeader("_sg_header_tn", "true");
            }
                        
            final Map<String, String> headerMap = new HashMap<>(Maps.filterKeys(origHeaders0, k->k!=null && (
                    k.equals(ConfigConstants.SG_CONF_REQUEST_HEADER)
                    || k.equals(ConfigConstants.SG_ORIGIN_HEADER)
                    || k.equals(ConfigConstants.SG_REMOTE_ADDRESS_HEADER)
                    || k.equals(ConfigConstants.SG_USER_HEADER)
                    || k.equals(ConfigConstants.SG_DLS_QUERY_HEADER)
                    || k.equals(ConfigConstants.SG_FLS_FIELDS_HEADER)
                    || k.equals(ConfigConstants.SG_MASKED_FIELD_HEADER)
                    || (k.equals("_sg_source_field_context") && ! (request instanceof SearchRequest) && !(request instanceof GetRequest))
                    || k.startsWith("_sg_trace")
                    || k.startsWith(ConfigConstants.SG_INITIAL_ACTION_CLASS_HEADER)
                    )));
            
            if (SearchGuardPlugin.GuiceHolder.getRemoteClusterService().isCrossClusterSearchEnabled() 
                    && clusterInfoHolder.isInitialized()
                    && action.startsWith(ClusterSearchShardsAction.NAME) 
                    && !clusterInfoHolder.hasNode(connection.getNode())) {
                headerMap.remove(ConfigConstants.SG_DLS_QUERY_HEADER);
                headerMap.remove(ConfigConstants.SG_MASKED_FIELD_HEADER);
                headerMap.remove(ConfigConstants.SG_FLS_FIELDS_HEADER);
            }
            
            if (SearchGuardPlugin.GuiceHolder.getRemoteClusterService().isCrossClusterSearchEnabled() 
                  && clusterInfoHolder.isInitialized()
                  && !action.startsWith("internal:") 
                  && !action.startsWith(ClusterSearchShardsAction.NAME) 
                  && !clusterInfoHolder.hasNode(connection.getNode())
                  && origResponseHeaders0 != null 
                  && origResponseHeaders0.size() > 0) {
                
                if (origResponseHeaders0.containsKey(ConfigConstants.SG_DLS_QUERY_HEADER)) {
                    headerMap.put(ConfigConstants.SG_DLS_QUERY_HEADER, origResponseHeaders0.get(ConfigConstants.SG_DLS_QUERY_HEADER).get(0));
                }
                if (origResponseHeaders0.containsKey(ConfigConstants.SG_MASKED_FIELD_HEADER)) {
                    headerMap.put(ConfigConstants.SG_MASKED_FIELD_HEADER, origResponseHeaders0.get(ConfigConstants.SG_MASKED_FIELD_HEADER).get(0));
                }
                if (origResponseHeaders0.containsKey(ConfigConstants.SG_FLS_FIELDS_HEADER)) {
                    headerMap.put(ConfigConstants.SG_FLS_FIELDS_HEADER, origResponseHeaders0.get(ConfigConstants.SG_FLS_FIELDS_HEADER).get(0));
                }
            }

            getThreadContext().putHeader(headerMap);

            ensureCorrectHeaders(remoteAdress0, user0, origin0);

            if(actionTrace.isTraceEnabled()) {
                getThreadContext().putHeader("_sg_trace"+System.currentTimeMillis()+"#"+UUID.randomUUID().toString(), Thread.currentThread().getName()+" IC -> "+action+" "+getThreadContext().getHeaders().entrySet().stream().filter(p->!p.getKey().startsWith("_sg_trace")).collect(Collectors.toMap(p -> p.getKey(), p -> p.getValue())));
            }

            sender.sendRequest(connection, action, request, options, restoringHandler);
        }
    }

    private void ensureCorrectHeaders(final Object remoteAdr, final User origUser, final String origin) {
        // keep original address

        if(origin != null && !origin.isEmpty() /*&& !Origin.LOCAL.toString().equalsIgnoreCase(origin)*/ && getThreadContext().getHeader(ConfigConstants.SG_ORIGIN_HEADER) == null) {
            getThreadContext().putHeader(ConfigConstants.SG_ORIGIN_HEADER, origin);
        }

        if(origin == null && getThreadContext().getHeader(ConfigConstants.SG_ORIGIN_HEADER) == null) {
            getThreadContext().putHeader(ConfigConstants.SG_ORIGIN_HEADER, Origin.LOCAL.toString());
        }

        if (remoteAdr != null && remoteAdr instanceof TransportAddress) {

            String remoteAddressHeader = getThreadContext().getHeader(ConfigConstants.SG_REMOTE_ADDRESS_HEADER);

            if(remoteAddressHeader == null) {
                getThreadContext().putHeader(ConfigConstants.SG_REMOTE_ADDRESS_HEADER, Base64Helper.serializeObject(((TransportAddress) remoteAdr).address()));
            }
        }

        if(origUser != null) {
            String userHeader = getThreadContext().getHeader(ConfigConstants.SG_USER_HEADER);

            if(userHeader == null) {
                getThreadContext().putHeader(ConfigConstants.SG_USER_HEADER, Base64Helper.serializeObject(origUser));
            }
        }
    }

    private ThreadContext getThreadContext() {
        return threadPool.getThreadContext();
    }

     //based on
    //org.elasticsearch.transport.TransportService.ContextRestoreResponseHandler<T>
    //which is private scoped
    private class RestoringTransportResponseHandler<T extends TransportResponse> implements TransportResponseHandler<T> {

        private final ThreadContext.StoredContext contextToRestore;
        private final TransportResponseHandler<T> innerHandler;

        private RestoringTransportResponseHandler(TransportResponseHandler<T> innerHandler, ThreadContext.StoredContext contextToRestore) {
            this.contextToRestore = contextToRestore;
            this.innerHandler = innerHandler;
        }

        @Override
        public T read(StreamInput in) throws IOException {
            return innerHandler.read(in);
        }

        @Override
        public void handleResponse(T response) {
            final List<String> flsResposneHeader = getThreadContext().getResponseHeaders().get(ConfigConstants.SG_FLS_FIELDS_HEADER);
            final List<String> dlsResponseHeader = getThreadContext().getResponseHeaders().get(ConfigConstants.SG_DLS_QUERY_HEADER);
            final List<String> maskedFieldsResponseHeader = getThreadContext().getResponseHeaders().get(ConfigConstants.SG_MASKED_FIELD_HEADER);

            contextToRestore.restore();

            if (response instanceof ClusterSearchShardsResponse && flsResposneHeader != null && !flsResposneHeader.isEmpty()) {
                getThreadContext().addResponseHeader(ConfigConstants.SG_FLS_FIELDS_HEADER, flsResposneHeader.get(0));
            }

            if (response instanceof ClusterSearchShardsResponse && dlsResponseHeader != null && !dlsResponseHeader.isEmpty()) {
                getThreadContext().addResponseHeader(ConfigConstants.SG_DLS_QUERY_HEADER, dlsResponseHeader.get(0));
            }
            
            if (response instanceof ClusterSearchShardsResponse && maskedFieldsResponseHeader != null && !maskedFieldsResponseHeader.isEmpty()) {
                getThreadContext().addResponseHeader(ConfigConstants.SG_MASKED_FIELD_HEADER, maskedFieldsResponseHeader.get(0));
            }

            innerHandler.handleResponse(response);
        }

        @Override
        public void handleException(TransportException e) {
            contextToRestore.restore();
            innerHandler.handleException(e);
        }

        @Override
        public String executor() {
            return innerHandler.executor();
        }
    }

}
