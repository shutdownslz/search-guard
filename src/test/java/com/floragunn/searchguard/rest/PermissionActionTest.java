package com.floragunn.searchguard.rest;

import org.apache.http.HttpStatus;
import org.elasticsearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Test;

import com.floragunn.searchguard.test.DynamicSgConfig;
import com.floragunn.searchguard.test.SingleClusterTest;
import com.floragunn.searchguard.test.helper.cluster.ClusterConfiguration;
import com.floragunn.searchguard.test.helper.rest.RestHelper;
import com.floragunn.searchguard.test.helper.rest.RestHelper.HttpResponse;

public class PermissionActionTest extends SingleClusterTest {

    @Test
    public void test() throws Exception {
        Settings settings = Settings.builder().build();

        setup(Settings.EMPTY, new DynamicSgConfig().setSgActionGroups("permissionsaction/sg_action_groups.yml")
                .setSgRoles("permissionsaction/sg_roles.yml").setSgRolesMapping("permissionsaction/sg_roles_mapping.yml"), settings, true, ClusterConfiguration.DEFAULT);

        RestHelper rh = nonSslRestHelper();
        
        HttpResponse response = rh.executeGetRequest("_searchguard/permission?permissions=kibana:saved_objects/x/read,kibana:saved_objects/x/write,kibana:foo/foo", encodeBasicHeader("worf", "worf"));
        
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertTrue(response.getBody().matches(".*\"kibana:saved_objects/x/read\":\\s*true.*"));
        Assert.assertTrue(response.getBody().matches(".*\"kibana:saved_objects/x/write\":\\s*false.*"));
        Assert.assertTrue(response.getBody().matches(".*\"kibana:foo/foo\":\\s*false.*"));
        
        response = rh.executeGetRequest("_searchguard/permission?permissions=kibana:saved_objects/x/read,kibana:saved_objects/x/write,kibana:foo/foo", encodeBasicHeader("kirk", "kirk"));
        
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertTrue(response.getBody().matches(".*\"kibana:saved_objects/x/read\":\\s*true.*"));        
        Assert.assertTrue(response.getBody().matches(".*\"kibana:saved_objects/x/write\":\\s*true.*"));
        Assert.assertTrue(response.getBody().matches(".*\"kibana:foo/foo\":\\s*false.*"));
    }

}
