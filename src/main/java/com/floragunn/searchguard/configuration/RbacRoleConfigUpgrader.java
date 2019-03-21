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
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.bulk.BulkResponse;
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

    private int roleUpdateCount = 0;
    private int roleMappingUpdateCount = 0;
    private Settings.Builder updatedRoleSettingsBuilder;
    private Settings.Builder updatedRoleMappingSettingsBuilder;
    private Tuple<Long, Settings> versionedRoleSettings;
    private Tuple<Long, Settings> versionedRoleMappingSettings;

    public RbacRoleConfigUpgrader(NodeClient client, IndexBaseConfigurationRepository indexBaseConfigurationRepository) {
        this.client = client;
        this.indexBaseConfigurationRepository = indexBaseConfigurationRepository;
    }

    public void handleUpgrade(ActionListener<BulkResponse> actionListener) throws IOException {

        Map<String, Tuple<Long, Settings>> versionedSettings = indexBaseConfigurationRepository
                .loadConfigurations(Arrays.asList(ConfigConstants.CONFIGNAME_ROLES, ConfigConstants.CONFIGNAME_ROLES_MAPPING), false);

        versionedRoleSettings = versionedSettings.get(ConfigConstants.CONFIGNAME_ROLES);
        versionedRoleMappingSettings = versionedSettings.get(ConfigConstants.CONFIGNAME_ROLES_MAPPING);

        Settings existingSettings = versionedRoleSettings.v2();

        updatedRoleSettingsBuilder = Settings.builder();
        updatedRoleSettingsBuilder.put(existingSettings);
        updatedRoleMappingSettingsBuilder = Settings.builder();
        updatedRoleMappingSettingsBuilder.put(versionedRoleMappingSettings.v2());

        Set<String> sgRoles = existingSettings.names();

        boolean hasApplicationsSection = this.hasApplicationsSection(sgRoles, existingSettings);

        log.info("Upgrading roles config:\nhasApplicationsSection: " + hasApplicationsSection + "\nversionedExistingSettings:\n"
                + versionedRoleSettings);

        for (String sgRole : sgRoles) {

            Settings tenants = existingSettings.getByPrefix(sgRole + ".tenants.");

            if (tenants != null) {
                handleTenantsOfRole(sgRole, tenants);
            }
        }

        if (!hasApplicationsSection && !sgRoles.contains("sg_kibana_user_all_application_access")) {
            createLegacyKibanaUserRole();
        }

        log.info("Upgraded roles config. " + roleUpdateCount + " changes.");

        if (roleUpdateCount != 0) {

            Map<String, Tuple<Long, BytesReference>> updatedConfig = new HashMap<>();

            updatedConfig.put(ConfigConstants.CONFIGNAME_ROLES,
                    Tuple.tuple(versionedRoleSettings.v1(), XContentHelper.toXContent(updatedRoleSettingsBuilder.build(), XContentType.JSON, false)));

            if (roleMappingUpdateCount != 0) {
                updatedConfig.put(ConfigConstants.CONFIGNAME_ROLES_MAPPING, Tuple.tuple(versionedRoleMappingSettings.v1(),
                        XContentHelper.toXContent(updatedRoleMappingSettingsBuilder.build(), XContentType.JSON, false)));

            }

            this.indexBaseConfigurationRepository.saveAndUpdateConfigurations(client, updatedConfig, actionListener);
        }
    }

    private void createLegacyKibanaUserRole() {
        log.info("Creating sg_kibana_user_all_application_access");

        updatedRoleSettingsBuilder.putList("sg_kibana_user_all_application_access.applications", Privileges.Defaults.DEFAULT_TENANT);
        roleUpdateCount++;

        updatedRoleMappingSettingsBuilder.putList("sg_kibana_user_all_application_access.users", Collections.singletonList("*"));
        roleMappingUpdateCount++;
    }

    private boolean hasApplicationsSection(Set<String> sgRoles, Settings existingSettings) {
        for (String sgRole : sgRoles) {
            if (existingSettings.get(sgRole + ".applications") != null) {
                return true;
            }
        }

        return false;
    }

    private void handleTenantsOfRole(String sgRole, Settings tenants) {
        for (String tenant : tenants.names()) {

            Settings tenantSettings = tenants.getAsSettings(tenant);

            if (!tenantSettings.isEmpty()) {
                // New style config
                continue;
            } else {
                // Legacy config

                updatedRoleSettingsBuilder.remove(sgRole + ".tenants." + tenant);

                // TODO check if used permissions are right

                String legacyTenantConfig = tenants.get(tenant, "RO");

                if ("RW".equalsIgnoreCase(legacyTenantConfig)) {
                    updatedRoleSettingsBuilder.putList(sgRole + ".tenants." + tenant + ".applications", Privileges.Defaults.TENANT_RW);
                } else {
                    updatedRoleSettingsBuilder.putList(sgRole + ".tenants." + tenant + ".applications", Privileges.Defaults.TENANT_RO);
                }

                roleUpdateCount++;
            }
        }
    }

}
