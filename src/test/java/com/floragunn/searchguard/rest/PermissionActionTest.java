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
                .setSgRoles("permissionsaction/sg_roles.yml").setSgRolesMapping("permissionsaction/sg_roles_mapping.yml"), settings, true,
                ClusterConfiguration.DEFAULT);

        RestHelper rh = nonSslRestHelper();

        HttpResponse response = rh.executeGetRequest(
                "_searchguard/permission?permissions=searchguard:dings/x/bums,searchguard:dings/x/bims,kibana:foo/foo",
                encodeBasicHeader("worf", "worf"));

        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertTrue(response.getBody().matches(".*\"searchguard:dings/x/bums\":\\s*true.*"));
        Assert.assertTrue(response.getBody().matches(".*\"searchguard:dings/x/bims\":\\s*false.*"));
        Assert.assertTrue(response.getBody().matches(".*\"kibana:foo/foo\":\\s*false.*"));

        response = rh.executeGetRequest("_searchguard/permission?permissions=searchguard:dings/x/bums,searchguard:dings/x/bims,kibana:foo/foo",
                encodeBasicHeader("kirk", "kirk"));

        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertTrue(response.getBody().matches(".*\"searchguard:dings/x/bums\":\\s*true.*"));
        Assert.assertTrue(response.getBody().matches(".*\"searchguard:dings/x/bims\":\\s*true.*"));
        Assert.assertTrue(response.getBody().matches(".*\"kibana:foo/foo\":\\s*false.*"));

        response = rh.executeGetRequest("_searchguard/permission?permissions=kibana:visualisations/foo/bar,kibana:graph/qux/quz,kibana:foo/foo",
                encodeBasicHeader("kirk", "kirk"));

        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertTrue(response.getBody().matches(".*\"kibana:visualisations/foo/bar\":\\s*true.*"));
        Assert.assertTrue(response.getBody().matches(".*\"kibana:graph/qux/quz\":\\s*true.*"));
        Assert.assertTrue(response.getBody().matches(".*\"kibana:foo/foo\":\\s*false.*"));
    }

}
