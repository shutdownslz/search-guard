/*
 * Copyright 2015-2018 floragunn GmbH
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

package com.floragunn.searchguard.configuration;

import java.io.IOException;
import java.util.Collections;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.index.IndexResponse;
import org.elasticsearch.client.node.NodeClient;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.XContentHelper;
import org.elasticsearch.common.xcontent.XContentType;

import com.floragunn.searchguard.privileges.Privileges;
import com.floragunn.searchguard.support.ConfigConstants;

public class RbacRoleConfigUpgrader {
    private final Logger log = LogManager.getLogger(this.getClass());
    private final IndexBaseConfigurationRepository indexBaseConfigurationRepository;
    private final NodeClient client;

    private int updateCount = 0;

    public RbacRoleConfigUpgrader(NodeClient client, IndexBaseConfigurationRepository indexBaseConfigurationRepository) {
        this.client = client;
        this.indexBaseConfigurationRepository = indexBaseConfigurationRepository;
    }

    public void handleUpgrade(ActionListener<IndexResponse> actionListener) throws IOException {

        Tuple<Long, Settings> versionedExistingSettings = indexBaseConfigurationRepository
                .loadConfigurations(Collections.singleton(ConfigConstants.CONFIGNAME_ROLES), false).get(ConfigConstants.CONFIGNAME_ROLES);
        Settings existingSettings = versionedExistingSettings.v2();

        Set<String> sgRoles = existingSettings.names();
        Settings.Builder updatedSettingsBuilder = Settings.builder();
        updatedSettingsBuilder.put(existingSettings);

        log.info("Upgrading roles config:\n" + versionedExistingSettings);

        for (String sgRole : sgRoles) {

            Settings tenants = existingSettings.getByPrefix(sgRole + ".tenants.");

            if (tenants != null) {
                handleTenantsOfRole(sgRole, tenants, updatedSettingsBuilder);
            }

            if ("sg_kibana_user".equals(sgRole) && existingSettings.getAsList(sgRole + ".applications") == null) {
                handleSgKibanaUserRole(sgRole, existingSettings, updatedSettingsBuilder);
            }
        }

        log.info("Upgraded roles config. " + updateCount + " changes.");

        if (updateCount != 0) {

            BytesReference updatedConfig = XContentHelper.toXContent(updatedSettingsBuilder.build(), XContentType.JSON, false);

            this.indexBaseConfigurationRepository.saveAndUpdateConfigurations(client, ConfigConstants.CONFIGNAME_ROLES, updatedConfig, actionListener,
                    versionedExistingSettings.v1());
        }
    }

    private void handleTenantsOfRole(String sgRole, Settings tenants, Settings.Builder updatedSettingsBuilder) {
        for (String tenant : tenants.names()) {

            Settings tenantSettings = tenants.getAsSettings(tenant);

            if (!tenantSettings.isEmpty()) {
                // New style config
                continue;
            } else {
                // Legacy config

                updatedSettingsBuilder.remove(sgRole + ".tenants." + tenant);

                // TODO check if used permissions are right

                String legacyTenantConfig = tenants.get(tenant, "RO");

                if ("RW".equalsIgnoreCase(legacyTenantConfig)) {
                    updatedSettingsBuilder.putList(sgRole + ".tenants." + tenant + ".applications", Privileges.Defaults.TENANT_RW);
                } else {
                    updatedSettingsBuilder.putList(sgRole + ".tenants." + tenant + ".applications", Privileges.Defaults.TENANT_RO);
                }

                updateCount++;
            }
        }
    }

    private void handleSgKibanaUserRole(String sgRole, Settings existingSettings, Settings.Builder updatedSettingsBuilder) {
        updatedSettingsBuilder.putList(sgRole + ".applications", Privileges.Defaults.DEFAULT_TENANT);
        updateCount++;
    }
}
