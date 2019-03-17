package com.floragunn.searchguard.configuration;

import java.util.Base64;

import org.apache.http.Header;
import org.apache.http.HttpStatus;
import org.elasticsearch.action.get.GetRequest;
import org.elasticsearch.client.transport.TransportClient;
import org.elasticsearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Test;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.test.DynamicSgConfig;
import com.floragunn.searchguard.test.SingleClusterTest;
import com.floragunn.searchguard.test.helper.file.FileHelper;
import com.floragunn.searchguard.test.helper.rest.RestHelper;
import com.floragunn.searchguard.test.helper.rest.RestHelper.HttpResponse;

public class RbacRoleConfigUpgraderTest extends SingleClusterTest {

    @Test
    public void testRolesUpgrade() throws Exception {
        ObjectMapper objectMapper = new ObjectMapper();
        Settings settings = Settings.builder()
                .put("searchguard.ssl.http.enabled",true)
                .put("searchguard.ssl.http.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.http.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("truststore.jks"))
                .build();
        
        setup(Settings.EMPTY, new DynamicSgConfig().setSgConfig("sg_config_clientcert.yml").setSgRoles("sg_roles_rbac_migration.yml"), settings,
                true);
        final RestHelper rh = restHelper();

        rh.keystore = "kirk-keystore.jks";
        rh.sendHTTPClientCertificate = true;

        try (TransportClient tc = getInternalTransportClient()) {
            String roles = new String(Base64.getDecoder().decode((String) tc.get(new GetRequest("searchguard", "sg", ConfigConstants.CONFIGNAME_ROLES)).actionGet().getSource().get(ConfigConstants.CONFIGNAME_ROLES)));
            JsonNode rolesJson = objectMapper.readTree(roles);
            JsonNode kibanaUserRole = rolesJson.get("sg_legacy_kibana_user");
            
            Assert.assertEquals(null, kibanaUserRole);
        }
        
        HttpResponse response = rh.executePostRequest("/_searchguard/kibanainfo", "{\"action\": \"formatUpgrade\"}", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        try (TransportClient tc = getInternalTransportClient()) {
            String roles = new String(Base64.getDecoder().decode((String) tc.get(new GetRequest("searchguard", "sg", ConfigConstants.CONFIGNAME_ROLES)).actionGet().getSource().get(ConfigConstants.CONFIGNAME_ROLES)));
            JsonNode rolesJson = objectMapper.readTree(roles);
            JsonNode kibanaUserRole = rolesJson.get("sg_legacy_kibana_user");
            JsonNode applications = kibanaUserRole.get("applications");
            
            Assert.assertEquals("kibana:ui:navLinks/*", applications.get(0).asText());
            Assert.assertEquals(1, applications.size());
        }

    }
    
    @Test
    public void testRolesUpgradeNoUpgrade() throws Exception {
        ObjectMapper objectMapper = new ObjectMapper();
        Settings settings = Settings.builder()
                .put("searchguard.ssl.http.enabled",true)
                .put("searchguard.ssl.http.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.http.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("truststore.jks"))
                .build();
        
        setup(Settings.EMPTY, new DynamicSgConfig().setSgConfig("sg_config_clientcert.yml").setSgRoles("sg_roles_rbac_no_migration.yml"), settings,
                true);
        final RestHelper rh = restHelper();

        rh.keystore = "kirk-keystore.jks";
        rh.sendHTTPClientCertificate = true;

        try (TransportClient tc = getInternalTransportClient()) {
            String roles = new String(Base64.getDecoder().decode((String) tc.get(new GetRequest("searchguard", "sg", ConfigConstants.CONFIGNAME_ROLES)).actionGet().getSource().get(ConfigConstants.CONFIGNAME_ROLES)));
            JsonNode rolesJson = objectMapper.readTree(roles);
            JsonNode kibanaUserRole = rolesJson.get("sg_legacy_kibana_user");
            
            Assert.assertNull(kibanaUserRole);
        }
        
        HttpResponse response = rh.executePostRequest("/_searchguard/kibanainfo", "{\"action\": \"formatUpgrade\"}", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        try (TransportClient tc = getInternalTransportClient()) {
            String roles = new String(Base64.getDecoder().decode((String) tc.get(new GetRequest("searchguard", "sg", ConfigConstants.CONFIGNAME_ROLES)).actionGet().getSource().get(ConfigConstants.CONFIGNAME_ROLES)));
            JsonNode rolesJson = objectMapper.readTree(roles);
            JsonNode kibanaUserRole = rolesJson.get("sg_legacy_kibana_user");
            
            Assert.assertNull(kibanaUserRole);
        }

    }
}