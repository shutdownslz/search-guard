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

package com.floragunn.searchguard.rest;

import static org.elasticsearch.rest.RestRequest.Method.GET;
import static org.elasticsearch.rest.RestRequest.Method.POST;

import java.io.IOException;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.index.IndexResponse;
import org.elasticsearch.client.node.NodeClient;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.common.util.concurrent.ThreadContext.StoredContext;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.rest.BaseRestHandler;
import org.elasticsearch.rest.BytesRestResponse;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestRequest.Method;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.threadpool.ThreadPool;

import com.floragunn.searchguard.configuration.AdminDNs;
import com.floragunn.searchguard.configuration.IndexBaseConfigurationRepository;
import com.floragunn.searchguard.configuration.RbacRoleConfigUpgrader;
import com.floragunn.searchguard.privileges.PrivilegesEvaluator;
import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.user.User;

public class KibanaInfoAction extends BaseRestHandler {

    private final Logger log = LogManager.getLogger(this.getClass());
    private final PrivilegesEvaluator evaluator;
    private final ThreadContext threadContext;
    private final IndexBaseConfigurationRepository indexBaseConfigurationRepository;
    private final AdminDNs adminDns;

    public KibanaInfoAction(final Settings settings, final RestController controller, final PrivilegesEvaluator evaluator,
            final IndexBaseConfigurationRepository indexBaseConfigurationRepository, final ThreadPool threadPool, final AdminDNs adminDns) {
        super(settings);
        this.threadContext = threadPool.getThreadContext();
        this.evaluator = evaluator;
        this.indexBaseConfigurationRepository = indexBaseConfigurationRepository;
        this.adminDns = adminDns;
        controller.registerHandler(GET, "/_searchguard/kibanainfo", this);
        controller.registerHandler(POST, "/_searchguard/kibanainfo", this);
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {

        if (request.method() == Method.POST) {
            return handlePost(request, client);
        } else {
            return handleGet(request, client);
        }

    }

    private RestChannelConsumer handleGet(RestRequest request, NodeClient client) throws IOException {
        return channel -> handleGet(channel);
    }

    private void handleGet(RestChannel channel) throws IOException {
        XContentBuilder builder = channel.newBuilder(); // NOSONAR
        BytesRestResponse response = null;
        try {

            final User user = (User) threadContext.getTransient(ConfigConstants.SG_USER);

            builder.startObject();
            builder.field("user_name", user == null ? null : user.getName());
            builder.field("not_fail_on_forbidden_enabled", evaluator.notFailOnForbiddenEnabled());
            builder.field("kibana_mt_enabled", evaluator.multitenancyEnabled());
            builder.field("kibana_index", evaluator.kibanaIndex());
            builder.field("kibana_server_user", evaluator.kibanaServerUsername());
            builder.field("rbac_enabled", evaluator.isRbacEnabled());

            int applicationPermissionFormatVersion = evaluator.getApplicationPermissionFormatVersion();

            builder.field("application_permission_format_version", applicationPermissionFormatVersion);
            builder.field("application_permission_migration_required",
                    evaluator.isRbacEnabled() && (applicationPermissionFormatVersion == -1 || applicationPermissionFormatVersion == 1));

            // builder.field("kibana_index_readonly", evaluator.kibanaIndexReadonly(user,
            // remoteAddress));
            builder.endObject();

            response = new BytesRestResponse(RestStatus.OK, builder);
        } catch (final Exception e1) {
            log.error(e1.toString(), e1);
            builder = channel.newBuilder(); // NOSONAR
            builder.startObject();
            builder.field("error", e1.toString());
            builder.endObject();
            response = new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, builder);
        } finally {
            if (builder != null) {
                builder.close();
            }
        }

        channel.sendResponse(response);
    }

    private RestChannelConsumer handlePost(RestRequest request, NodeClient client) throws IOException {
        XContentParser contentParser = request.contentParser();

        Map<String, Object> structuredMap = contentParser.map();

        if ("formatUpgrade".equalsIgnoreCase(String.valueOf(structuredMap.get("action")))) {
            return handleUpgrade(request, client);
        } else {
            return handleGet(request, client);
        }
    }

    private RestChannelConsumer handleUpgrade(RestRequest request, NodeClient client) throws IOException {

        final User user = (User) threadContext.getTransient(ConfigConstants.SG_USER);

        if (user == null || (!user.getName().equals(evaluator.kibanaServerUsername())) && !adminDns.isAdmin(user)) {

            return channel -> channel.sendResponse(new BytesRestResponse(RestStatus.FORBIDDEN, ""));
        }

        final Object originalUser = this.threadContext.getTransient(ConfigConstants.SG_USER);
        final Object originalRemoteAddress = this.threadContext.getTransient(ConfigConstants.SG_REMOTE_ADDRESS);
        final Object originalOrigin = this.threadContext.getTransient(ConfigConstants.SG_ORIGIN);

        return channel -> {

            try (StoredContext ctx = this.threadContext.stashContext()) {

                this.threadContext.putHeader(ConfigConstants.SG_CONF_REQUEST_HEADER, "true");
                this.threadContext.putTransient(ConfigConstants.SG_USER, originalUser);
                this.threadContext.putTransient(ConfigConstants.SG_REMOTE_ADDRESS, originalRemoteAddress);
                this.threadContext.putTransient(ConfigConstants.SG_ORIGIN, originalOrigin);

                RbacRoleConfigUpgrader configUpgrader = new RbacRoleConfigUpgrader(client, indexBaseConfigurationRepository);
                configUpgrader.handleUpgrade(new ActionListener<IndexResponse>() {

                    @Override
                    public void onResponse(IndexResponse response) {
                        try {
                            handleGet(channel);
                        } catch (Exception e) {
                            onFailure(e);
                        }
                    }

                    @Override
                    public void onFailure(Exception e) {
                        channel.sendResponse(new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, e.getMessage()));
                    }
                });
            }
        };

    }

    @Override
    public String getName() {
        return "Kibana Info Action";
    }

}
