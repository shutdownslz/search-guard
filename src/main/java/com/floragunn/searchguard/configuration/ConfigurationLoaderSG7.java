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

package com.floragunn.searchguard.configuration;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Function;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.RuntimeCryptoException;
import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.get.GetResponse;
import org.elasticsearch.action.get.MultiGetItemResponse;
import org.elasticsearch.action.get.MultiGetRequest;
import org.elasticsearch.action.get.MultiGetResponse;
import org.elasticsearch.action.get.MultiGetResponse.Failure;
import org.elasticsearch.client.Client;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.common.xcontent.ToXContent;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentHelper;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.threadpool.ThreadPool;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.floragunn.searchguard.DefaultObjectMapper;
import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.support.SearchGuardDeprecationHandler;
import com.google.common.collect.ImmutableSet;

public class ConfigurationLoaderSG7 {

    protected final Logger log = LogManager.getLogger(this.getClass());
    private final Client client;
	//private final ThreadContext threadContext;
    private final String searchguardIndex;
    
    ConfigurationLoaderSG7(final Client client, ThreadPool threadPool, final Settings settings) {
        super();
        this.client = client;
        //this.threadContext = threadPool.getThreadContext();
        this.searchguardIndex = settings.get(ConfigConstants.SEARCHGUARD_CONFIG_INDEX_NAME, ConfigConstants.SG_DEFAULT_CONFIG_INDEX);
        log.debug("Index is: {}", searchguardIndex);
    }
    
    Map<String, DynamicConfiguration> load(final String[] events, long timeout, TimeUnit timeUnit) throws InterruptedException, TimeoutException {
        final CountDownLatch latch = new CountDownLatch(events.length);
        final Map<String, DynamicConfiguration> rs = new HashMap<String, DynamicConfiguration>(events.length);
        
        loadAsync(events, new ConfigCallback() {
            
            @Override
            public void success(DynamicConfiguration dConf) {
                if(latch.getCount() <= 0) {
                    log.error("Latch already counted down (for {} of {})  (index={})", dConf.type, Arrays.toString(events), searchguardIndex);
                }
                
                rs.put(dConf.type, dConf);
                latch.countDown();
                if(log.isDebugEnabled()) {
                    log.debug("Received config for {} (of {}) with current latch value={}", dConf.type, Arrays.toString(events), latch.getCount());
                }
            }
            
            @Override
            public void singleFailure(Failure failure) {
                log.error("Failure {} retrieving configuration for {} (index={})", failure==null?null:failure.getMessage(), Arrays.toString(events), searchguardIndex);
            }
            
            @Override
            public void noData(String id) {
                log.warn("No data for {} while retrieving configuration for {}  (index={})", id, Arrays.toString(events), searchguardIndex);
            }
            
            @Override
            public void failure(Throwable t) {
                log.error("Exception {} while retrieving configuration for {}  (index={})",t,t.toString(), Arrays.toString(events), searchguardIndex);
            }
        });
        
        if(!latch.await(timeout, timeUnit)) {
            //timeout
            throw new TimeoutException("Timeout after "+timeout+""+timeUnit+" while retrieving configuration for "+Arrays.toString(events)+ "(index="+searchguardIndex+")");
        }
        
        return rs;
    }
    
    void loadAsync(final String[] events, final ConfigCallback callback) {
        if(events == null || events.length == 0) {
            log.warn("No config events requested to load");
            return;
        }
        
        final MultiGetRequest mget = new MultiGetRequest();

        for (int i = 0; i < events.length; i++) {
            final String event = events[i];
            mget.add(searchguardIndex, event);
        }
        
        mget.refresh(true);
        mget.realtime(true);
        
        client.multiGet(mget, new ActionListener<MultiGetResponse>() {
            @Override
            public void onResponse(MultiGetResponse response) {
                MultiGetItemResponse[] responses = response.getResponses();
                for (int i = 0; i < responses.length; i++) {
                    MultiGetItemResponse singleResponse = responses[i];
                    if(singleResponse != null && !singleResponse.isFailed()) {
                        GetResponse singleGetResponse = singleResponse.getResponse();
                        if(singleGetResponse.isExists() && !singleGetResponse.isSourceEmpty()) {
                            //success
                            final DynamicConfiguration dConf = toConfig(singleGetResponse);
                            if(dConf != null) {
                                callback.success(dConf);
                            } else {
                                log.error("Cannot parse settings for "+singleGetResponse.getId());
                            }
                        } else {
                            //does not exist or empty source
                            callback.noData(singleGetResponse.getId());
                        }
                    } else {
                        //failure
                        callback.singleFailure(singleResponse==null?null:singleResponse.getFailure());
                    }
                }
            }
            
            @Override
            public void onFailure(Exception e) {
                callback.failure(e);
            }
        });
        
    }

    private DynamicConfiguration toConfig(GetResponse singleGetResponse) {
        final BytesReference ref = singleGetResponse.getSourceAsBytesRef();
        final String id = singleGetResponse.getId();
        final long version = singleGetResponse.getVersion();
        

        if (ref == null || ref.length() == 0) {
            log.error("Empty or null byte reference for {}", id);
            return null;
        }
        
        XContentParser parser = null;

        try {
            parser = XContentHelper.createParser(NamedXContentRegistry.EMPTY, SearchGuardDeprecationHandler.INSTANCE, ref, XContentType.JSON);
            parser.nextToken();
            parser.nextToken();
         
            if(!id.equals((parser.currentName()))) {
                log.error("Cannot parse config for type {} because {}!={}", id, id, parser.currentName());
                return null;
            }
            
            parser.nextToken();
            
            final JsonNode jsonNode = DefaultObjectMapper.objectMapper.readTree(new ByteArrayInputStream(parser.binaryValue()));

            return new DynamicConfiguration(jsonNode, version, id);
        } catch (final IOException e) {
            throw ExceptionsHelper.convertToElastic(e);
        } finally {
            if(parser != null) {
                try {
                    parser.close();
                } catch (IOException e) {
                    //ignore
                }
            }
        }
    }
    
    public static class DynamicConfiguration implements ToXContent{
        
        private static final TypeReference<HashMap<String,Object>> typeRefMSO = new TypeReference<HashMap<String,Object>>() {};
        private static final TypeReference<HashMap<String,String>> typeRefMSS = new TypeReference<HashMap<String,String>>() {};

        
        private final JsonNode jsonNode;
        private final long version;
        private final String type;
        
        public DynamicConfiguration(JsonNode jsonNode, long version, String type) {
            super();
            this.jsonNode = jsonNode;
            this.version = version;
            this.type = type;
            
            if(isEmpty()) {
                //throw new RuntimeException("empty config for: "+type);
            }
            
            /*System.out.println(jsonNode.size()+" elements for "+jsonNode.getNodeType()+" and "+type);
            
            try {
                System.out.println(DefaultObjectMapper.objectMapper.writeValueAsString(jsonNode));
            } catch (JsonProcessingException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
            */
        }

        public static Function<String, String> checkKeyFunction() {
            return in -> {
                
                if(in != null && in.contains(".")) {
                    throw new RuntimeException("No dots allowed in keys ("+in+")");
                }
                
                return in;
            };
        }
        
        public String getAsStringWithDefault(String defaultValue, String... path) {
            return jsonNode.at(toJsonPointer(path)).asText(defaultValue);
        }
        
        public String getAsString(String... path) {
            return getAsStringWithDefault(null, path);
        }

        public boolean getAsBoolean(boolean b, String... string) {
            return jsonNode.at(toJsonPointer(string)).asBoolean(b);
        }


        public List<String> getAsList(List<String> defaultList, String... string) {
           JsonNode n = jsonNode.at(toJsonPointer(string));
           
           if(n != null && n.isArray()) {
               List<String> ret = new ArrayList<String>(n.size());
               Iterator<JsonNode> it = ((ArrayNode) n).iterator();
               while(it.hasNext()) {
                   ret.add(it.next().asText());
               }
               return Collections.unmodifiableList(ret);
           }
           
           return defaultList;
        }


        public List<String> getAsListWithEmptyDefault(String... entry) {
            return getAsList(Collections.emptyList(), entry);
        }

        public DynamicConfiguration getByPrefix0(String... string) {
            return new DynamicConfiguration(jsonNode.at(toJsonPointer(string)), version, type);
        }


        public Map<String, DynamicConfiguration> getGroups0(String... string) {
            final Map<String, DynamicConfiguration> ret = new HashMap<>();
            final JsonNode node = jsonNode.at(toJsonPointer(string));
            for(String n: ImmutableSet.copyOf(node.fieldNames())) {
                ret.put(n, new DynamicConfiguration(node.get(n), version, type));
            }
            return Collections.unmodifiableMap(ret);
        }


        public boolean isEmpty() {
            return jsonNode.size() == 0;
        }


        public Set<String> names() {
           return ImmutableSet.copyOf(jsonNode.fieldNames());
        }


        public String toDelimitedString0(char c) {
            // TODO Auto-generated method stub
            return null;
        }


        @Override
        public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
            builder.map(getAsMap(""));
            return builder;
        }


        public int getAsInt(int i, String... string) {
            return jsonNode.at(toJsonPointer(string)).asInt(i);
        }
        
        public Map<String, Object> getAsMap0(String... string) {
            Map<String, Object> map = DefaultObjectMapper.objectMapper.convertValue(jsonNode.at(toJsonPointer(string)), typeRefMSO);
            return map==null?null:Collections.unmodifiableMap(map);
        }
        
        public Map<String, String> getAsStringMap0(String... string) {
            Map<String, String> map = DefaultObjectMapper.objectMapper.convertValue(jsonNode.at(toJsonPointer(string)), typeRefMSS);
            return map==null?Collections.emptyMap():Collections.unmodifiableMap(map);
        }
    
        private String toJsonPointer(String[] in) {
            if(in == null) {
                return null;
            }

            if(in.startsWith(".")) {
                
                throw new RuntimeException(in+" must not start with a dot");
                //return "/."+in.substring(1).replace('.', '/');
            } else if(in.startsWith("/")) {
                throw new RuntimeException(in+" must not start with a slash");
                //return in.replace('.', '/');
            } else if(in.endsWith(".")) {
                
                throw new RuntimeException(in+" must not end with a dot");
                //return "/."+in.substring(1).replace('.', '/');
            } else if(in.endsWith("/")) {
                throw new RuntimeException(in+" must not end with a slash");
                //return in.replace('.', '/');
            } else {
                //rfc6901 escaping
                return "/"+in.replace("~", "~0").replace("/", "~1").replace('.', '/');
            }
        }

        @Override
        public String toString() {
            try {
                return "DynamicConfiguration [jsonNode=" + DefaultObjectMapper.objectMapper.writeValueAsString(jsonNode) + ", version=" + version + ", type=" + type + "]";
            } catch (JsonProcessingException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
                return e.getMessage();
            }
        }

        
        
        
    }
    
    public enum ConfigType {
        
    }
}
