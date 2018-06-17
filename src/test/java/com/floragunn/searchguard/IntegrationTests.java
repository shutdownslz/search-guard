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

package com.floragunn.searchguard;

import java.lang.Thread.UncaughtExceptionHandler;
import java.util.TreeSet;

import org.apache.http.Header;
import org.apache.http.HttpStatus;
import org.apache.http.message.BasicHeader;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.action.DocWriteResponse.Result;
import org.elasticsearch.action.admin.cluster.node.info.NodesInfoRequest;
import org.elasticsearch.action.admin.cluster.reroute.ClusterRerouteRequest;
import org.elasticsearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.elasticsearch.action.admin.indices.alias.IndicesAliasesRequest.AliasActions;
import org.elasticsearch.action.admin.indices.create.CreateIndexRequest;
import org.elasticsearch.action.admin.indices.create.CreateIndexResponse;
import org.elasticsearch.action.admin.indices.mapping.put.PutMappingRequest;
import org.elasticsearch.action.get.GetResponse;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.index.IndexResponse;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.action.search.SearchResponse;
import org.elasticsearch.action.support.WriteRequest.RefreshPolicy;
import org.elasticsearch.client.transport.TransportClient;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.unit.TimeValue;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.common.util.concurrent.ThreadContext.StoredContext;
import org.elasticsearch.common.xcontent.XContentType;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;

import com.floragunn.searchguard.action.configupdate.ConfigUpdateAction;
import com.floragunn.searchguard.action.configupdate.ConfigUpdateRequest;
import com.floragunn.searchguard.action.configupdate.ConfigUpdateResponse;
import com.floragunn.searchguard.action.whoami.WhoAmIAction;
import com.floragunn.searchguard.action.whoami.WhoAmIRequest;
import com.floragunn.searchguard.action.whoami.WhoAmIResponse;
import com.floragunn.searchguard.configuration.PrivilegesInterceptorImpl;
import com.floragunn.searchguard.http.HTTPClientCertAuthenticator;
import com.floragunn.searchguard.ssl.util.ExceptionUtils;
import com.floragunn.searchguard.ssl.util.SSLConfigConstants;
import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.test.DynamicSgConfig;
import com.floragunn.searchguard.test.SingleClusterTest;
import com.floragunn.searchguard.test.helper.file.FileHelper;
import com.floragunn.searchguard.test.helper.rest.RestHelper;
import com.floragunn.searchguard.test.helper.rest.RestHelper.HttpResponse;

import io.netty.handler.ssl.OpenSsl;

public class IntegrationTests extends SingleClusterTest {

    @Test
    public void testSearchScroll() throws Exception {
        
        Thread.setDefaultUncaughtExceptionHandler(new UncaughtExceptionHandler() {
            
            @Override
            public void uncaughtException(Thread t, Throwable e) {
                e.printStackTrace();
                
            }
        });
        
    final Settings settings = Settings.builder()
            .putList(ConfigConstants.SEARCHGUARD_AUTHCZ_REST_IMPERSONATION_USERS+".worf", "knuddel","nonexists")
            .build();
    setup(settings);
    final RestHelper rh = nonSslRestHelper();

        try (TransportClient tc = getInternalTransportClient()) {                    
            for(int i=0; i<3; i++)
            tc.index(new IndexRequest("vulcangov").type("kolinahr").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();                
        }
        
        
        System.out.println("########search");
        HttpResponse res;
        Assert.assertEquals(HttpStatus.SC_OK, (res=rh.executeGetRequest("vulcangov/_search?scroll=1m&pretty=true", encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());
        
        System.out.println(res.getBody());
        int start = res.getBody().indexOf("_scroll_id") + 15;
        String scrollid = res.getBody().substring(start, res.getBody().indexOf("\"", start+1));
        System.out.println(scrollid);
        System.out.println("########search scroll");
        Assert.assertEquals(HttpStatus.SC_OK, (res=rh.executePostRequest("/_search/scroll?pretty=true", "{\"scroll_id\" : \""+scrollid+"\"}", encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());


        System.out.println("########search done");
        
        
    }
    
    @Test
    public void testHTTPBasic() throws Exception {
        final Settings settings = Settings.builder()
                .putList(ConfigConstants.SEARCHGUARD_AUTHCZ_REST_IMPERSONATION_USERS+".worf", "knuddel","nonexists")
                .build();
        setup(settings);
        final RestHelper rh = nonSslRestHelper();
    
            try (TransportClient tc = getInternalTransportClient()) {                    
                tc.admin().indices().create(new CreateIndexRequest("copysf")).actionGet();         
                tc.index(new IndexRequest("vulcangov").type("kolinahr").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();                
                tc.index(new IndexRequest("starfleet").type("ships").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
                tc.index(new IndexRequest("starfleet_academy").type("students").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
                tc.index(new IndexRequest("starfleet_library").type("public").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
                tc.index(new IndexRequest("klingonempire").type("ships").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
                tc.index(new IndexRequest("public").type("legends").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
     
                tc.index(new IndexRequest("spock").type("type01").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
                tc.index(new IndexRequest("kirk").type("type01").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
                tc.index(new IndexRequest("role01_role02").type("type01").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
    
                tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().indices("starfleet","starfleet_academy","starfleet_library").alias("sf"))).actionGet();
                tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().indices("klingonempire","vulcangov").alias("nonsf"))).actionGet();
                tc.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(AliasActions.add().indices("public").alias("unrestricted"))).actionGet();

            }
            
            Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, rh.executeGetRequest("").getStatusCode());
            Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, rh.executeGetRequest("_search").getStatusCode());
            Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("", encodeBasicHeader("worf", "worf")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_OK, rh.executeDeleteRequest("nonexistentindex*", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest(".nonexistentindex*", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePutRequest("searchguard/config/2", "{}",encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_NOT_FOUND, rh.executeGetRequest("searchguard/config/0", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_NOT_FOUND, rh.executeGetRequest("xxxxyyyy/config/0", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("", encodeBasicHeader("abc", "abc:abc")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, rh.executeGetRequest("", encodeBasicHeader("userwithnopassword", "")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, rh.executeGetRequest("", encodeBasicHeader("userwithblankpassword", "")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, rh.executeGetRequest("", encodeBasicHeader("worf", "wrongpasswd")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, rh.executeGetRequest("", new BasicHeader("Authorization", "Basic "+"wrongheader")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, rh.executeGetRequest("", new BasicHeader("Authorization", "Basic ")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, rh.executeGetRequest("", new BasicHeader("Authorization", "Basic")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, rh.executeGetRequest("", new BasicHeader("Authorization", "")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("", encodeBasicHeader("picard", "picard")).getStatusCode());
    
            for(int i=0; i< 10; i++) {
                Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, rh.executeGetRequest("", encodeBasicHeader("worf", "wrongpasswd")).getStatusCode());
            }
    
            Assert.assertEquals(HttpStatus.SC_OK, rh.executePutRequest("/theindex","{}",encodeBasicHeader("theindexadmin", "theindexadmin")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_CREATED, rh.executePutRequest("/theindex/type/1?refresh=true","{\"a\":0}",encodeBasicHeader("theindexadmin", "theindexadmin")).getStatusCode());
            //Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("/theindex/_analyze?text=this+is+a+test",encodeBasicHeader("theindexadmin", "theindexadmin")).getStatusCode());
            //Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executeGetRequest("_analyze?text=this+is+a+test",encodeBasicHeader("theindexadmin", "theindexadmin")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_OK, rh.executeDeleteRequest("/theindex",encodeBasicHeader("theindexadmin", "theindexadmin")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executeDeleteRequest("/klingonempire",encodeBasicHeader("theindexadmin", "theindexadmin")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executeGetRequest("starfleet/_search", encodeBasicHeader("worf", "worf")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executeGetRequest("_search", encodeBasicHeader("worf", "worf")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("starfleet/ships/_search?pretty", encodeBasicHeader("worf", "worf")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executeDeleteRequest("searchguard/", encodeBasicHeader("worf", "worf")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePostRequest("/searchguard/_close", null,encodeBasicHeader("worf", "worf")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePostRequest("/searchguard/_upgrade", null,encodeBasicHeader("worf", "worf")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePutRequest("/searchguard/_mapping/config","{}",encodeBasicHeader("worf", "worf")).getStatusCode());
    
            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executeGetRequest("searchguard/", encodeBasicHeader("worf", "worf")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePutRequest("searchguard/config/2", "{}",encodeBasicHeader("worf", "worf")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executeGetRequest("searchguard/config/0",encodeBasicHeader("worf", "worf")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executeDeleteRequest("searchguard/config/0",encodeBasicHeader("worf", "worf")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePutRequest("searchguard/config/0","{}",encodeBasicHeader("worf", "worf")).getStatusCode());
            
            HttpResponse resc = rh.executeGetRequest("_cat/indices/public?v",encodeBasicHeader("bug108", "nagilum"));
            Assert.assertTrue(resc.getBody().contains("green"));
            Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
            
            Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("role01_role02/type01/_search?pretty",encodeBasicHeader("user_role01_role02_role03", "user_role01_role02_role03")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executeGetRequest("role01_role02/type01/_search?pretty",encodeBasicHeader("user_role01", "user_role01")).getStatusCode());
    
            Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("spock/type01/_search?pretty",encodeBasicHeader("spock", "spock")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executeGetRequest("spock/type01/_search?pretty",encodeBasicHeader("kirk", "kirk")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("kirk/type01/_search?pretty",encodeBasicHeader("kirk", "kirk")).getStatusCode());

    //all  
            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePutRequest("_mapping/config","{\"i\" : [\"4\"]}",encodeBasicHeader("worf", "worf")).getStatusCode());
            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executePostRequest("searchguard/_mget","{\"ids\" : [\"0\"]}",encodeBasicHeader("worf", "worf")).getStatusCode());
            
            Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("starfleet/ships/_search?pretty", encodeBasicHeader("worf", "worf")).getStatusCode());
    
            try (TransportClient tc = getInternalTransportClient()) {       
                tc.index(new IndexRequest("searchguard").type("sg").id("roles").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("roles", FileHelper.readYamlContent("sg_roles_deny.yml"))).actionGet();
                ConfigUpdateResponse cur = tc.execute(ConfigUpdateAction.INSTANCE, new ConfigUpdateRequest(new String[]{"roles"})).actionGet();
                Assert.assertEquals(3, cur.getNodes().size());
            }
            
            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executeGetRequest("starfleet/ships/_search?pretty", encodeBasicHeader("worf", "worf")).getStatusCode());
    
            try (TransportClient tc = getInternalTransportClient()) {
                tc.index(new IndexRequest("searchguard").type("sg").id("roles").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("roles", FileHelper.readYamlContent("sg_roles.yml"))).actionGet();
                ConfigUpdateResponse cur = tc.execute(ConfigUpdateAction.INSTANCE, new ConfigUpdateRequest(new String[]{"roles"})).actionGet();
                Assert.assertEquals(3, cur.getNodes().size());
            }
            
            Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("starfleet/ships/_search?pretty", encodeBasicHeader("worf", "worf")).getStatusCode());
            HttpResponse res = rh.executeGetRequest("_search?pretty", encodeBasicHeader("nagilum", "nagilum"));
            Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
            Assert.assertTrue(res.getBody().contains("\"total\" : 9"));
            Assert.assertTrue(!res.getBody().contains("searchguard"));
            
            res = rh.executeGetRequest("_nodes/stats?pretty", encodeBasicHeader("nagilum", "nagilum"));
            Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
            Assert.assertTrue(res.getBody().contains("total_in_bytes"));
            Assert.assertTrue(res.getBody().contains("max_file_descriptors"));
            Assert.assertTrue(res.getBody().contains("buffer_pools"));
            Assert.assertFalse(res.getBody().contains("\"nodes\" : { }"));
            
            res = rh.executePostRequest("*/_upgrade", "", encodeBasicHeader("nagilum", "nagilum"));
            System.out.println(res.getBody());
            System.out.println(res.getStatusReason());
            Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
            
            String bulkBody = 
                "{ \"index\" : { \"_index\" : \"test\", \"_type\" : \"type1\", \"_id\" : \"1\" } }"+System.lineSeparator()+
                "{ \"field1\" : \"value1\" }" +System.lineSeparator()+
                "{ \"index\" : { \"_index\" : \"test\", \"_type\" : \"type1\", \"_id\" : \"2\" } }"+System.lineSeparator()+
                "{ \"field2\" : \"value2\" }"+System.lineSeparator();
    
            res = rh.executePostRequest("_bulk", bulkBody, encodeBasicHeader("writer", "writer"));
            System.out.println(res.getBody());
            Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());  
            Assert.assertTrue(res.getBody().contains("\"errors\":false"));
            Assert.assertTrue(res.getBody().contains("\"status\":201"));  
            
            res = rh.executeGetRequest("_searchguard/authinfo", new BasicHeader("sg_tenant", "unittesttenant"), encodeBasicHeader("worf", "worf"));
            Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
            Assert.assertTrue(res.getBody().contains("sg_tenants"));
            Assert.assertTrue(res.getBody().contains("unittesttenant"));
            Assert.assertTrue(res.getBody().contains("\"kltentrw\":true"));
            Assert.assertTrue(res.getBody().contains("\"user_name\":\"worf\""));
            
            res = rh.executeGetRequest("_searchguard/authinfo", encodeBasicHeader("worf", "worf"));
            Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
            Assert.assertTrue(res.getBody().contains("sg_tenants"));
            Assert.assertTrue(res.getBody().contains("\"user_requested_tenant\":null"));
            Assert.assertTrue(res.getBody().contains("\"kltentrw\":true"));
            Assert.assertTrue(res.getBody().contains("\"user_name\":\"worf\""));
            Assert.assertTrue(res.getBody().contains("\"custom_attribute_names\":[]"));
            Assert.assertFalse(res.getBody().contains("attributes="));
            Assert.assertTrue(PrivilegesInterceptorImpl.count > 0);
            
            res = rh.executeGetRequest("_searchguard/authinfo?pretty", encodeBasicHeader("custattr", "nagilum"));
            Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
            Assert.assertTrue(res.getBody().contains("sg_tenants"));
            Assert.assertTrue(res.getBody().contains("\"user_requested_tenant\" : null"));
            Assert.assertTrue(res.getBody().contains("\"user_name\" : \"custattr\""));
            Assert.assertTrue(res.getBody().contains("\"custom_attribute_names\" : ["));
            Assert.assertTrue(res.getBody().contains("attr.internal.c3"));
            Assert.assertTrue(res.getBody().contains("attr.internal.c1"));
            Assert.assertTrue(PrivilegesInterceptorImpl.count > 0);
            
            final String reindex = "{"+
                    "\"source\": {"+    
                      "\"index\": \"starfleet\""+
                    "},"+
                    "\"dest\": {"+
                      "\"index\": \"copysf\""+
                    "}"+
                  "}";
    
            res = rh.executePostRequest("_reindex?pretty", reindex, encodeBasicHeader("nagilum", "nagilum"));
            Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
            Assert.assertTrue(res.getBody().contains("\"total\" : 1"));
            Assert.assertTrue(res.getBody().contains("\"batches\" : 1"));
            Assert.assertTrue(res.getBody().contains("\"failures\" : [ ]"));
            
            //rest impersonation
            res = rh.executeGetRequest("/_searchguard/authinfo", new BasicHeader("sg_impersonate_as","knuddel"), encodeBasicHeader("worf", "worf"));
            Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
            Assert.assertTrue(res.getBody().contains("name=knuddel"));
            Assert.assertFalse(res.getBody().contains("worf"));
            
            res = rh.executeGetRequest("/_searchguard/authinfo", new BasicHeader("sg_impersonate_as","nonexists"), encodeBasicHeader("worf", "worf"));
            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, res.getStatusCode());
            
            res = rh.executeGetRequest("/_searchguard/authinfo", new BasicHeader("sg_impersonate_as","notallowed"), encodeBasicHeader("worf", "worf"));
            Assert.assertEquals(HttpStatus.SC_FORBIDDEN, res.getStatusCode());
        }

    @Test
        public void testTransportClient() throws Exception {
        
        final Settings settings = Settings.builder()
                .putList(ConfigConstants.SEARCHGUARD_AUTHCZ_IMPERSONATION_DN+".CN=spock,OU=client,O=client,L=Test,C=DE", "worf", "nagilum")
                .build();
        setup(settings);
    
            try (TransportClient tc = getInternalTransportClient()) {                    
                tc.index(new IndexRequest("starfleet").type("ships").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            }
            
             
            Settings tcSettings = Settings.builder()
                    .put(settings)
                    .put("searchguard.ssl.transport.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("spock-keystore.jks"))
                    .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS,"spock")
                    .build();
    
            System.out.println("------- 0 ---------");
            
            try (TransportClient tc = getInternalTransportClient(clusterInfo, tcSettings)) {         

                Assert.assertEquals(3, tc.admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().size());
                
                System.out.println("------- 1 ---------");
                
                CreateIndexResponse cir = tc.admin().indices().create(new CreateIndexRequest("vulcan")).actionGet();
                Assert.assertTrue(cir.isAcknowledged());
                
                System.out.println("------- 2 ---------");
                
                IndexResponse ir = tc.index(new IndexRequest("vulcan").type("secrets").id("s1").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"secret\":true}", XContentType.JSON)).actionGet();
                Assert.assertTrue(ir.getResult() == Result.CREATED);
                
                System.out.println("------- 3 ---------");
                
                GetResponse gr =tc.prepareGet("vulcan", "secrets", "s1").setRealtime(true).get();
                Assert.assertTrue(gr.isExists());
                
                System.out.println("------- 4 ---------");
                
                gr =tc.prepareGet("vulcan", "secrets", "s1").setRealtime(false).get();
                Assert.assertTrue(gr.isExists());
                
                System.out.println("------- 5 ---------");
                
                SearchResponse actionGet = tc.search(new SearchRequest("vulcan").types("secrets")).actionGet();
                Assert.assertEquals(1, actionGet.getHits().getHits().length);
                System.out.println("------- 6 ---------");
                
                gr =tc.prepareGet("searchguard", "sg", "config").setRealtime(false).get();
                Assert.assertFalse(gr.isExists());
                
                System.out.println("------- 7 ---------");
                
                gr =tc.prepareGet("searchguard", "sg", "config").setRealtime(true).get();
                Assert.assertFalse(gr.isExists());
                
                System.out.println("------- 8 ---------");
                
                actionGet = tc.search(new SearchRequest("searchguard")).actionGet();
                Assert.assertEquals(0, actionGet.getHits().getHits().length);
                
                System.out.println("------- 9 ---------");
                
                try {
                    tc.index(new IndexRequest("searchguard").type("sg").id("config").source("config", FileHelper.readYamlContent("sg_config.yml"))).actionGet();
                    Assert.fail();
                } catch (Exception e) {
                    System.out.println(e.getMessage());
                }
                
                System.out.println("------- 10 ---------");
                
                //impersonation
                try {
                    
                    StoredContext ctx = tc.threadPool().getThreadContext().stashContext();
                    try {
                        tc.threadPool().getThreadContext().putHeader("sg_impersonate_as", "worf");
                        gr = tc.prepareGet("vulcan", "secrets", "s1").get();
                    } finally {
                        ctx.close();
                    }
                    Assert.fail();
                } catch (ElasticsearchSecurityException e) {
                   Assert.assertTrue(e.getMessage(), e.getMessage().startsWith("no permissions for [indices:data/read/get]"));
                }
                
                System.out.println("------- 11 ---------");
       
                StoredContext ctx = tc.threadPool().getThreadContext().stashContext();
                try {
                    Header header = encodeBasicHeader("worf", "worf");
                    tc.threadPool().getThreadContext().putHeader(header.getName(), header.getValue());
                    gr = tc.prepareGet("vulcan", "secrets", "s1").get();
                    Assert.fail();
                } catch (ElasticsearchSecurityException e) {
                    Assert.assertTrue(e.getMessage().startsWith("no permissions for [indices:data/read/get]"));
                } finally {
                    ctx.close();
                }
                
                System.out.println("------- 12 ---------");
                ctx = tc.threadPool().getThreadContext().stashContext();
                try {
                    Header header = encodeBasicHeader("worf", "worf111");
                    tc.threadPool().getThreadContext().putHeader(header.getName(), header.getValue());
                    gr = tc.prepareGet("vulcan", "secrets", "s1").get();
                    Assert.fail();
                } catch (ElasticsearchSecurityException e) {
                    e.printStackTrace();
                   //Assert.assertTrue(e.getCause().getMessage().contains("password does not match"));
                } finally {
                    ctx.close();
                }
                
                System.out.println("------- 13 ---------");       
                
                //impersonation
                try {
                    ctx = tc.threadPool().getThreadContext().stashContext();
                    try {
                        tc.threadPool().getThreadContext().putHeader("sg_impersonate_as", "gkar");
                        gr = tc.prepareGet("vulcan", "secrets", "s1").get();
                        Assert.fail();
                    } finally {
                        ctx.close();
                    }
    
                } catch (ElasticsearchSecurityException e) {
                    Assert.assertEquals("'CN=spock,OU=client,O=client,L=Test,C=DE' is not allowed to impersonate as 'gkar'", e.getMessage());
                }

                System.out.println("------- 12 ---------");
    
                ctx = tc.threadPool().getThreadContext().stashContext();
                try {
                    tc.threadPool().getThreadContext().putHeader("sg_impersonate_as", "nagilum");
                    gr = tc.prepareGet("searchguard", "sg", "config").setRealtime(Boolean.TRUE).get();
                    Assert.assertFalse(gr.isExists());
                    Assert.assertTrue(gr.isSourceEmpty());
                } finally {
                    ctx.close();
                }
    
                System.out.println("------- 13 ---------");
                ctx = tc.threadPool().getThreadContext().stashContext();
                try {
                    tc.threadPool().getThreadContext().putHeader("sg_impersonate_as", "nagilum");
                    gr = tc.prepareGet("searchguard", "config", "0").setRealtime(Boolean.FALSE).get();
                    Assert.assertFalse(gr.isExists());
                    Assert.assertTrue(gr.isSourceEmpty());
                } finally {
                    ctx.close();
                }
                System.out.println("------- 13.1 ---------");
                
                String scrollId = null;
                ctx = tc.threadPool().getThreadContext().stashContext();
                try {
                    tc.threadPool().getThreadContext().putHeader("sg_impersonate_as", "nagilum");
                    SearchResponse searchRes = tc.prepareSearch("starfleet").setTypes("ships").setScroll(TimeValue.timeValueMinutes(5)).get();
                    scrollId = searchRes.getScrollId();
                } finally {
                    ctx.close();
                }
                
                System.out.println("------- 13.2 ---------");
    
                ctx = tc.threadPool().getThreadContext().stashContext();
                try {
                    tc.threadPool().getThreadContext().putHeader("sg_impersonate_as", "nagilum");
                    tc.prepareSearchScroll(scrollId).get();
                } finally {
                    ctx.close();
                }
                
                       
                System.out.println("------- 14 ---------");
                
                boolean ok=false;
                ctx = tc.threadPool().getThreadContext().stashContext();
                try {
                    tc.threadPool().getThreadContext().putHeader("sg_impersonate_as", "nagilum");
                    gr = tc.prepareGet("vulcan", "secrets", "s1").get();
                    ok = true;
                    ctx.close();
                    ctx = tc.threadPool().getThreadContext().stashContext();
                    tc.threadPool().getThreadContext().putHeader("sg_impersonate_as", "nagilum");
                    Header header = encodeBasicHeader("worf", "worf");
                    tc.threadPool().getThreadContext().putHeader(header.getName(), header.getValue());
                    gr = tc.prepareGet("vulcan", "secrets", "s1").get();
                    Assert.fail();
                } catch (ElasticsearchSecurityException e) {
                    Assert.assertTrue(e.getMessage().startsWith("no permissions for [indices:data/read/get]"));
                   Assert.assertTrue(ok);
                } finally {
                    ctx.close();
                }
                
                System.out.println("------- 15 ---------");
                ctx = tc.threadPool().getThreadContext().stashContext();
                try {
                    tc.threadPool().getThreadContext().putHeader("sg_impersonate_as", "nagilum");
                    gr = tc.prepareGet("searchguard", "sg", "config").setRealtime(Boolean.TRUE).get();
                    Assert.assertFalse(gr.isExists());
                    Assert.assertTrue(gr.isSourceEmpty());
                } finally {
                    ctx.close();
                }
                
                System.out.println("------- 15 0---------");
                
                ctx = tc.threadPool().getThreadContext().stashContext();
                try {
                    Header header = encodeBasicHeader("worf", "worf");
                    tc.threadPool().getThreadContext().putHeader(header.getName(), header.getValue());
                    gr = tc.prepareGet("searchguard", "sg", "config").setRealtime(Boolean.TRUE).get();
                    Assert.fail();
                } catch (Exception e) {
                    Assert.assertTrue(e.getMessage().contains("no permissions for [indices:data/read/get] and User [name=worf"));
                }
                finally {
                    ctx.close();
                }
                
                
                System.out.println("------- 15 1---------");
                
                ctx = tc.threadPool().getThreadContext().stashContext();
                try {
                    Header header = encodeBasicHeader("nagilum", "nagilum");
                    tc.threadPool().getThreadContext().putHeader(header.getName(), header.getValue());
                    gr = tc.prepareGet("searchguard", "sg", "config").setRealtime(Boolean.TRUE).get();
                    Assert.assertFalse(gr.isExists());
                    Assert.assertTrue(gr.isSourceEmpty());
                } finally {
                    ctx.close();
                }
                
                System.out.println("------- 16---------");
              
                ctx = tc.threadPool().getThreadContext().stashContext();
                try {
                    tc.threadPool().getThreadContext().putHeader("sg_impersonate_as", "nagilum");
                    gr = tc.prepareGet("searchguard", "sg", "config").setRealtime(Boolean.FALSE).get();
                    Assert.assertFalse(gr.isExists());
                    Assert.assertTrue(gr.isSourceEmpty());
                } finally {
                    ctx.close();
                }
                
                ctx = tc.threadPool().getThreadContext().stashContext();
                SearchResponse searchRes = null;
                try {
                    tc.threadPool().getThreadContext().putHeader("sg_impersonate_as", "nagilum");
                    searchRes = tc.prepareSearch("starfleet").setTypes("ships").setScroll(TimeValue.timeValueMinutes(5)).get();
                } finally {
                    ctx.close();
                }
                
                Assert.assertNotNull(searchRes.getScrollId());
                
                ctx = tc.threadPool().getThreadContext().stashContext();
                try {
                    tc.threadPool().getThreadContext().putHeader("sg_impersonate_as", "worf");
                    tc.prepareSearchScroll(searchRes.getScrollId()).get(); 
                    Assert.fail();
                } catch (Exception e) {
                    Throwable root = ExceptionUtils.getRootCause(e);
                    e.printStackTrace();
                    Assert.assertTrue(root.getMessage().contains("Wrong user in scroll context"));
                }
                finally {
                    ctx.close();
                }

                
                ctx = tc.threadPool().getThreadContext().stashContext();
                searchRes = null;
                try {
                    tc.threadPool().getThreadContext().putHeader("sg_impersonate_as", "nagilum");
                    searchRes = tc.prepareSearch("starfleet").setTypes("ships").setScroll(TimeValue.timeValueMinutes(5)).get();
                    SearchResponse scrollRes = tc.prepareSearchScroll(searchRes.getScrollId()).get();
                    Assert.assertEquals(0, scrollRes.getFailedShards());
                } finally {
                    ctx.close();
                }
    
                System.out.println("------- TRC end ---------");
            }
            
            System.out.println("------- CTC end ---------");
        }

    @Test
    public void testEnsureInitViaRestDoesWork() throws Exception {
        
        final Settings settings = Settings.builder()
                .put(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_CLIENTAUTH_MODE, "REQUIRE")
                .put("searchguard.ssl.http.enabled",true)
                .put("searchguard.ssl.http.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.http.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("truststore.jks"))
                .build();
        setup(Settings.EMPTY, null, settings, false);
        final RestHelper rh = restHelper(); //ssl resthelper

        rh.enableHTTPClientSSL = true;
        rh.trustHTTPServerCertificate = true;
        rh.sendHTTPClientCertificate = true;
        Assert.assertEquals(HttpStatus.SC_SERVICE_UNAVAILABLE, rh.executePutRequest("searchguard/config/0", "{}", encodeBasicHeader("___", "")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_SERVICE_UNAVAILABLE, rh.executePutRequest("searchguard/sg/config", "{}", encodeBasicHeader("___", "")).getStatusCode());
        
        
        rh.keystore = "kirk-keystore.jks";
        Assert.assertEquals(HttpStatus.SC_CREATED, rh.executePutRequest("searchguard/sg/config", "{}", encodeBasicHeader("___", "")).getStatusCode());
    
        Assert.assertFalse(rh.executeSimpleRequest("_nodes/stats?pretty").contains("\"tx_size_in_bytes\" : 0"));
        Assert.assertFalse(rh.executeSimpleRequest("_nodes/stats?pretty").contains("\"rx_count\" : 0"));
        Assert.assertFalse(rh.executeSimpleRequest("_nodes/stats?pretty").contains("\"rx_size_in_bytes\" : 0"));
        Assert.assertFalse(rh.executeSimpleRequest("_nodes/stats?pretty").contains("\"tx_count\" : 0"));

    }

    @Test
    public void testComposite() throws Exception {
    
        setup(Settings.EMPTY, new DynamicSgConfig().setSgConfig("sg_composite_config.yml").setSgRoles("sg_roles_composite.yml"), Settings.EMPTY, true);
        final RestHelper rh = nonSslRestHelper();
    
        try (TransportClient tc = getInternalTransportClient()) {                
            tc.index(new IndexRequest("starfleet").type("ships").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();           
            tc.index(new IndexRequest("klingonempire").type("ships").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();      
            tc.index(new IndexRequest("public").type("legends").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();            
        }
        
        String msearchBody = 
                "{\"index\":\"starfleet\", \"type\":\"ships\", \"ignore_unavailable\": true}"+System.lineSeparator()+
                "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"+System.lineSeparator()+
                "{\"index\":\"klingonempire\", \"type\":\"ships\", \"ignore_unavailable\": true}"+System.lineSeparator()+
                "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"+System.lineSeparator()+
                "{\"index\":\"public\", \"ignore_unavailable\": true}"+System.lineSeparator()+
                "{\"size\":10, \"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}"+System.lineSeparator();
                         
            
        HttpResponse resc = rh.executePostRequest("_msearch", msearchBody, encodeBasicHeader("worf", "worf"));
        Assert.assertEquals(200, resc.getStatusCode());
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("\"_index\":\"klingonempire\""));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("hits"));
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("no permissions for [indices:data/read/search]"));
        
    }
    
    @Test
    public void testWhoAmI() throws Exception {
        setup(Settings.EMPTY, new DynamicSgConfig().setSgInternalUsers("sg_internal_empty.yml")
                .setSgRoles("sg_roles_deny.yml"), Settings.EMPTY, true);
        
        try (TransportClient tc = getUserTransportClient(clusterInfo, "spock-keystore.jks", Settings.EMPTY)) {  
            WhoAmIResponse wres = tc.execute(WhoAmIAction.INSTANCE, new WhoAmIRequest()).actionGet();  
            System.out.println(wres);
            Assert.assertEquals(wres.toString(), "CN=spock,OU=client,O=client,L=Test,C=DE", wres.getDn());
            Assert.assertFalse(wres.toString(), wres.isAdmin());
            Assert.assertFalse(wres.toString(), wres.isAuthenticated());
            Assert.assertFalse(wres.toString(), wres.isNodeCertificateRequest());

        }
        
        try (TransportClient tc = getUserTransportClient(clusterInfo, "node-0-keystore.jks", Settings.EMPTY)) {  
            WhoAmIResponse wres = tc.execute(WhoAmIAction.INSTANCE, new WhoAmIRequest()).actionGet();    
            System.out.println(wres);
            Assert.assertEquals(wres.toString(), "CN=node-0.example.com,OU=SSL,O=Test,L=Test,C=DE", wres.getDn());
            Assert.assertFalse(wres.toString(), wres.isAdmin());
            Assert.assertFalse(wres.toString(), wres.isAuthenticated());
            Assert.assertTrue(wres.toString(), wres.isNodeCertificateRequest());

        }
    }
    
    @Test
    public void testNotInsecure() throws Exception {
        setup(Settings.EMPTY, new DynamicSgConfig().setSgRoles("sg_roles_deny.yml"), Settings.EMPTY, true);
        final RestHelper rh = nonSslRestHelper();
        
        try (TransportClient tc = getInternalTransportClient()) {               
            //create indices and mapping upfront
            tc.index(new IndexRequest("test").type("type1").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"field2\":\"init\"}", XContentType.JSON)).actionGet();           
            tc.index(new IndexRequest("lorem").type("type1").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"field2\":\"init\"}", XContentType.JSON)).actionGet();      
        
            WhoAmIResponse wres = tc.execute(WhoAmIAction.INSTANCE, new WhoAmIRequest()).actionGet();   
            System.out.println(wres);
            Assert.assertEquals("CN=kirk,OU=client,O=client,L=Test,C=DE", wres.getDn());
            Assert.assertTrue(wres.isAdmin());
            Assert.assertTrue(wres.toString(), wres.isAuthenticated());
            Assert.assertFalse(wres.toString(), wres.isNodeCertificateRequest());
        }
        
        HttpResponse res = rh.executePutRequest("test/_mapping/type1?pretty", "{\"properties\": {\"name\":{\"type\":\"text\"}}}", encodeBasicHeader("writer", "writer"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, res.getStatusCode());  
        
        res = rh.executePostRequest("_cluster/reroute", "{}", encodeBasicHeader("writer", "writer"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, res.getStatusCode());  
        
        try (TransportClient tc = getUserTransportClient(clusterInfo, "spock-keystore.jks", Settings.EMPTY)) {               
            //create indices and mapping upfront
            try {
                tc.admin().indices().putMapping(new PutMappingRequest("test").type("typex").source("fieldx","type=text")).actionGet();
                Assert.fail();
            } catch (ElasticsearchSecurityException e) {
                Assert.assertTrue(e.toString(),e.getMessage().contains("no permissions for"));
            }          
            
            try {
                tc.admin().cluster().reroute(new ClusterRerouteRequest()).actionGet();
                Assert.fail();
            } catch (ElasticsearchSecurityException e) {
                Assert.assertTrue(e.toString(),e.getMessage().contains("no permissions for [cluster:admin/reroute]"));
            }
            
            WhoAmIResponse wres = tc.execute(WhoAmIAction.INSTANCE, new WhoAmIRequest()).actionGet();                
            Assert.assertEquals("CN=spock,OU=client,O=client,L=Test,C=DE", wres.getDn());
            Assert.assertFalse(wres.isAdmin());
            Assert.assertTrue(wres.toString(), wres.isAuthenticated());
            Assert.assertFalse(wres.toString(), wres.isNodeCertificateRequest());
        }

    }
    
    @Test
    public void testDnParsingCertAuth() throws Exception {
        Settings settings = Settings.builder()
                .put("username_attribute", "cn")
                .put("roles_attribute", "l")
                .build();
        HTTPClientCertAuthenticator auth = new HTTPClientCertAuthenticator(settings, null);
        Assert.assertEquals("abc", auth.extractCredentials(null, newThreadContext("cn=abc,cn=xxx,l=ert,st=zui,c=qwe")).getUsername());
        Assert.assertEquals("abc", auth.extractCredentials(null, newThreadContext("cn=abc,l=ert,st=zui,c=qwe")).getUsername());
        Assert.assertEquals("abc", auth.extractCredentials(null, newThreadContext("CN=abc,L=ert,st=zui,c=qwe")).getUsername());     
        Assert.assertEquals("abc", auth.extractCredentials(null, newThreadContext("l=ert,cn=abc,st=zui,c=qwe")).getUsername());
        Assert.assertNull(auth.extractCredentials(null, newThreadContext("L=ert,CN=abc,c,st=zui,c=qwe")));
        Assert.assertEquals("abc", auth.extractCredentials(null, newThreadContext("l=ert,st=zui,c=qwe,cn=abc")).getUsername());
        Assert.assertEquals("abc", auth.extractCredentials(null, newThreadContext("L=ert,st=zui,c=qwe,CN=abc")).getUsername()); 
        Assert.assertEquals("L=ert,st=zui,c=qwe", auth.extractCredentials(null, newThreadContext("L=ert,st=zui,c=qwe")).getUsername()); 
        Assert.assertArrayEquals(new String[] {"ert"}, auth.extractCredentials(null, newThreadContext("cn=abc,l=ert,st=zui,c=qwe")).getBackendRoles().toArray(new String[0]));
        Assert.assertArrayEquals(new String[] {"bleh", "ert"}, new TreeSet<>(auth.extractCredentials(null, newThreadContext("cn=abc,l=ert,L=bleh,st=zui,c=qwe")).getBackendRoles()).toArray(new String[0]));
        
        settings = Settings.builder()
                .build();
        auth = new HTTPClientCertAuthenticator(settings, null);
        Assert.assertEquals("cn=abc,l=ert,st=zui,c=qwe", auth.extractCredentials(null, newThreadContext("cn=abc,l=ert,st=zui,c=qwe")).getUsername());
    }
    
    private ThreadContext newThreadContext(String sslPrincipal) {
        ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
        threadContext.putTransient(ConfigConstants.SG_SSL_PRINCIPAL, sslPrincipal);
        return threadContext;
    }

    @Test
    public void testDNSpecials() throws Exception {
    
        final Settings settings = Settings.builder()
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_FILEPATH, FileHelper.getAbsoluteFilePathFromClassPath("node-untspec5-keystore.p12"))
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS, "1")
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_TYPE, "PKCS12")
                .putList("searchguard.nodes_dn", "EMAILADDRESS=unt@tst.com,CN=node-untspec5.example.com,OU=SSL,O=Te\\, st,L=Test,C=DE")
                .putList("searchguard.authcz.admin_dn", "EMAILADDRESS=unt@xxx.com,CN=node-untspec6.example.com,OU=SSL,O=Te\\, st,L=Test,C=DE")
                .put("searchguard.cert.oid","1.2.3.4.5.6")
                .build();
        
        
        Settings tcSettings = Settings.builder()
                .put("searchguard.ssl.transport.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("node-untspec6-keystore.p12"))
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_TYPE, "PKCS12")
                .build();
        
        setup(tcSettings, new DynamicSgConfig(), settings, true);
        RestHelper rh = nonSslRestHelper();
        
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, rh.executeGetRequest("").getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("", encodeBasicHeader("worf", "worf")).getStatusCode());
    
    }
    
    @Test
    public void testDNSpecials1() throws Exception {
    
        final Settings settings = Settings.builder()
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_FILEPATH, FileHelper.getAbsoluteFilePathFromClassPath("node-untspec5-keystore.p12"))
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS, "1")
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_TYPE, "PKCS12")
                .putList("searchguard.nodes_dn", "EMAILADDRESS=unt@tst.com,CN=node-untspec5.example.com,OU=SSL,O=Te\\, st,L=Test,C=DE")
                .putList("searchguard.authcz.admin_dn", "EMAILADDREss=unt@xxx.com,  cn=node-untspec6.example.com, OU=SSL,O=Te\\, st,L=Test, c=DE")
                .put("searchguard.cert.oid","1.2.3.4.5.6")
                .build();
        
        
        Settings tcSettings = Settings.builder()
                .put("searchguard.ssl.transport.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("node-untspec6-keystore.p12"))
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_TYPE, "PKCS12")
                .build();
        
        setup(tcSettings, new DynamicSgConfig(), settings, true);
        RestHelper rh = nonSslRestHelper();
        
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, rh.executeGetRequest("").getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("", encodeBasicHeader("worf", "worf")).getStatusCode());
    }

    @Test
    public void testEnsureOpenSSLAvailability() {
        Assume.assumeTrue(allowOpenSSL);
        Assert.assertTrue(String.valueOf(OpenSsl.unavailabilityCause()), OpenSsl.isAvailable());
    }

    @Test
    public void testMultiget() throws Exception {
    
        setup();
    
        try (TransportClient tc = getInternalTransportClient()) {
            tc.index(new IndexRequest("mindex1").type("type").id("1").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("mindex2").type("type").id("2").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":2}", XContentType.JSON)).actionGet();
        }
    
        //sg_multiget -> picard
        
        
            String mgetBody = "{"+
            "\"docs\" : ["+
                "{"+
                     "\"_index\" : \"mindex1\","+
                    "\"_type\" : \"type\","+
                    "\"_id\" : \"1\""+
               " },"+
               " {"+
                   "\"_index\" : \"mindex2\","+
                   " \"_type\" : \"type\","+
                   " \"_id\" : \"2\""+
                "}"+
            "]"+
        "}";
       
       RestHelper rh = nonSslRestHelper();
       HttpResponse resc = rh.executePostRequest("_mget?refresh=true", mgetBody, encodeBasicHeader("picard", "picard"));
       System.out.println(resc.getBody());
       Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
       Assert.assertFalse(resc.getBody().contains("type2"));
        
    }

    @Test
    public void testRestImpersonation() throws Exception {
    
        final Settings settings = Settings.builder()
                 .putList(ConfigConstants.SEARCHGUARD_AUTHCZ_REST_IMPERSONATION_USERS+".spock", "knuddel","userwhonotexists").build();
 
        setup(settings);
        
        RestHelper rh = nonSslRestHelper();
        
        //knuddel:
        //    hash: _rest_impersonation_only_
    
        HttpResponse resp;
        resp = rh.executeGetRequest("/_searchguard/authinfo", new BasicHeader("sg_impersonate_as", "knuddel"), encodeBasicHeader("worf", "worf"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, resp.getStatusCode());
    
        resp = rh.executeGetRequest("/_searchguard/authinfo", new BasicHeader("sg_impersonate_as", "knuddel"), encodeBasicHeader("spock", "spock"));
        Assert.assertEquals(HttpStatus.SC_OK, resp.getStatusCode());
        Assert.assertTrue(resp.getBody().contains("name=knuddel"));
        Assert.assertFalse(resp.getBody().contains("spock"));
        
        resp = rh.executeGetRequest("/_searchguard/authinfo", new BasicHeader("sg_impersonate_as", "userwhonotexists"), encodeBasicHeader("spock", "spock"));
        System.out.println(resp.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, resp.getStatusCode());
    
        resp = rh.executeGetRequest("/_searchguard/authinfo", new BasicHeader("sg_impersonate_as", "invalid"), encodeBasicHeader("spock", "spock"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, resp.getStatusCode());
    }

    @Test
    public void testSingle() throws Exception {
    
        setup();
    
        try (TransportClient tc = getInternalTransportClient()) {          
            tc.index(new IndexRequest("shakespeare").type("type").id("1").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
                      
            ConfigUpdateResponse cur = tc.execute(ConfigUpdateAction.INSTANCE, new ConfigUpdateRequest(new String[]{"config","roles","rolesmapping","internalusers","actiongroups"})).actionGet();
            Assert.assertEquals(clusterInfo.numNodes, cur.getNodes().size());
        }
    
        RestHelper rh = nonSslRestHelper();
        //sg_shakespeare -> picard
    
        HttpResponse resc = rh.executeGetRequest("shakespeare/_search", encodeBasicHeader("picard", "picard"));
        System.out.println(resc.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
        Assert.assertTrue(resc.getBody().contains("\"content\":1"));
        
        resc = rh.executeHeadRequest("shakespeare", encodeBasicHeader("picard", "picard"));
        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
        
    }

    @Test
    public void testSpecialUsernames() throws Exception {
    
        setup();    
        RestHelper rh = nonSslRestHelper();
        
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("", encodeBasicHeader("bug.99", "nagilum")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, rh.executeGetRequest("", encodeBasicHeader("a", "b")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("", encodeBasicHeader("\"'+-,;_?*@<>!$%&/()=#", "nagilum")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("", encodeBasicHeader("§ÄÖÜäöüß", "nagilum")).getStatusCode());
    
    }

    @Test
    public void testXff() throws Exception {
    
        setup(Settings.EMPTY, new DynamicSgConfig().setSgConfig("sg_config_xff.yml"), Settings.EMPTY, true);
        RestHelper rh = nonSslRestHelper();
        HttpResponse resc = rh.executeGetRequest("_searchguard/authinfo", new BasicHeader("x-forwarded-for", "10.0.0.7"), encodeBasicHeader("worf", "worf"));
        Assert.assertEquals(200, resc.getStatusCode());
        Assert.assertTrue(resc.getBody().contains("10.0.0.7"));
    }

    @Test
    public void testRegexExcludes() throws Exception {
        
        setup(Settings.EMPTY, new DynamicSgConfig(), Settings.EMPTY);

        try (TransportClient tc = getInternalTransportClient(this.clusterInfo, Settings.EMPTY)) {
            tc.index(new IndexRequest("indexa").type("type01").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"indexa\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("indexb").type("type01").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"indexb\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("isallowed").type("type01").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"isallowed\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("special").type("type01").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"special\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("alsonotallowed").type("type01").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"alsonotallowed\":1}", XContentType.JSON)).actionGet();
        }
        
        RestHelper rh = nonSslRestHelper();
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("index*/_search",encodeBasicHeader("rexclude", "nagilum")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("indexa/_search",encodeBasicHeader("rexclude", "nagilum")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("isallowed/_search",encodeBasicHeader("rexclude", "nagilum")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executeGetRequest("special/_search",encodeBasicHeader("rexclude", "nagilum")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, rh.executeGetRequest("alsonotallowed/_search",encodeBasicHeader("rexclude", "nagilum")).getStatusCode());
    }
    
    @Test
    public void testMultiRoleSpan() throws Exception {
        
        setup();
        final RestHelper rh = nonSslRestHelper();

        try (TransportClient tc = getInternalTransportClient()) {    
            tc.index(new IndexRequest("mindex_1").type("logs").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("mindex_2").type("logs").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":2}", XContentType.JSON)).actionGet();
        }
        
        HttpResponse res = rh.executeGetRequest("/mindex_1,mindex_2/_search", encodeBasicHeader("mindex12", "nagilum"));
        System.out.println(res.getBody());
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, res.getStatusCode());
        Assert.assertFalse(res.getBody().contains("\"content\":1"));
        Assert.assertFalse(res.getBody().contains("\"content\":2"));
        
        try (TransportClient tc = getInternalTransportClient()) {                                       
            tc.index(new IndexRequest("searchguard").type("sg").id("config").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("config", FileHelper.readYamlContent("sg_config_multirolespan.yml"))).actionGet();
   
            ConfigUpdateResponse cur = tc.execute(ConfigUpdateAction.INSTANCE, new ConfigUpdateRequest(new String[]{"config"})).actionGet();
            Assert.assertEquals(clusterInfo.numNodes, cur.getNodes().size());
        }
        
        res = rh.executeGetRequest("/mindex_1,mindex_2/_search", encodeBasicHeader("mindex12", "nagilum"));
        System.out.println(res.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
        Assert.assertTrue(res.getBody().contains("\"content\":1"));
        Assert.assertTrue(res.getBody().contains("\"content\":2"));
        
    }
    
    @Test
    public void testMultiRoleSpan2() throws Exception {
        
        setup(Settings.EMPTY, new DynamicSgConfig().setSgConfig("sg_config_multirolespan.yml"), Settings.EMPTY);
        final RestHelper rh = nonSslRestHelper();

        try (TransportClient tc = getInternalTransportClient()) {                                       
            tc.index(new IndexRequest("mindex_1").type("logs").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":1}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("mindex_2").type("logs").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":2}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("mindex_3").type("logs").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":2}", XContentType.JSON)).actionGet();
            tc.index(new IndexRequest("mindex_4").type("logs").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"content\":2}", XContentType.JSON)).actionGet();
        }
        
        HttpResponse res = rh.executeGetRequest("/mindex_1,mindex_2/_search", encodeBasicHeader("mindex12", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
        
        res = rh.executeGetRequest("/mindex_1,mindex_3/_search", encodeBasicHeader("mindex12", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, res.getStatusCode());

        res = rh.executeGetRequest("/mindex_1,mindex_4/_search", encodeBasicHeader("mindex12", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, res.getStatusCode());
         
    }
    
    @Test
    public void testSGUnderscore() throws Exception {
        
        setup();
        final RestHelper rh = nonSslRestHelper();
        
        HttpResponse res = rh.executePostRequest("abc_xyz_2018_05_24/logs/1", "{\"content\":1}", encodeBasicHeader("underscore", "nagilum"));
        
        res = rh.executeGetRequest("abc_xyz_2018_05_24/logs/1", encodeBasicHeader("underscore", "nagilum"));
        Assert.assertTrue(res.getBody(),res.getBody().contains("\"content\":1"));
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
        res = rh.executeGetRequest("abc_xyz_2018_05_24/_refresh", encodeBasicHeader("underscore", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
        res = rh.executeGetRequest("aaa_bbb_2018_05_24/_refresh", encodeBasicHeader("underscore", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, res.getStatusCode());
    }

}
