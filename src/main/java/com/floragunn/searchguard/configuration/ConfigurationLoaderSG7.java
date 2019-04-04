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

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
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
import org.elasticsearch.common.xcontent.XContentHelper;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.threadpool.ThreadPool;

import com.floragunn.searchguard.sgconf.impl.CType;
import com.floragunn.searchguard.sgconf.impl.SgDynamicConfiguration;
import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.support.SearchGuardDeprecationHandler;

public class ConfigurationLoaderSG7 {

    protected final Logger log = LogManager.getLogger(this.getClass());
    private final Client client;
    private final String searchguardIndex;
    
    ConfigurationLoaderSG7(final Client client, ThreadPool threadPool, final Settings settings) {
        super();
        this.client = client;
        this.searchguardIndex = settings.get(ConfigConstants.SEARCHGUARD_CONFIG_INDEX_NAME, ConfigConstants.SG_DEFAULT_CONFIG_INDEX);
        log.debug("Index is: {}", searchguardIndex);
    }
    
    Map<CType, SgDynamicConfiguration<?>> load(final CType[] events, long timeout, TimeUnit timeUnit) throws InterruptedException, TimeoutException {
        final CountDownLatch latch = new CountDownLatch(events.length);
        final Map<CType, SgDynamicConfiguration<?>> rs = new HashMap<>(events.length);
        
        loadAsync(events, new ConfigCallback() {
            
            @Override
            public void success(SgDynamicConfiguration<?> dConf) {
                if(latch.getCount() <= 0) {
                    log.error("Latch already counted down (for {} of {})  (index={})", dConf.getCType().toLCString(), Arrays.toString(events), searchguardIndex);
                }
                
                rs.put(dConf.getCType(), dConf);
                latch.countDown();
                if(log.isDebugEnabled()) {
                    log.debug("Received config for {} (of {}) with current latch value={}", dConf.getCType().toLCString(), Arrays.toString(events), latch.getCount());
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
    
    void loadAsync(final CType[] events, final ConfigCallback callback) {
        if(events == null || events.length == 0) {
            log.warn("No config events requested to load");
            return;
        }
        
        final MultiGetRequest mget = new MultiGetRequest();

        for (int i = 0; i < events.length; i++) {
            final String event = events[i].toLCString();
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
                            try {
                                final SgDynamicConfiguration<?> dConf = toConfig(singleGetResponse);
                                if(dConf != null) {
                                    callback.success(dConf.deepClone());
                                } else {
                                    log.error("Cannot parse settings for "+singleGetResponse.getId());
                                }
                            } catch (Exception e) {
                                log.error(e.toString(),e);
                                callback.failure(e);
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

    private SgDynamicConfiguration<?> toConfig(GetResponse singleGetResponse) {
        final BytesReference ref = singleGetResponse.getSourceAsBytesRef();
        final String id = singleGetResponse.getId();
        final long seqNo = singleGetResponse.getSeqNo();
        final long primaryTerm = singleGetResponse.getPrimaryTerm();
        
        

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

            if (CType.ACTIONGROUPS.toLCString().equals(id)) {

                try {
                    return SgDynamicConfiguration.fromJson(new String(parser.binaryValue(), "UTF-8"), CType.fromString(id), 1, seqNo, primaryTerm);
                } catch (Exception e) {
                    return SgDynamicConfiguration.fromJson(new String(parser.binaryValue(), "UTF-8"), CType.fromString(id), 0, seqNo, primaryTerm);
                }
            }

            return SgDynamicConfiguration.fromJson(new String(parser.binaryValue(), "UTF-8"), CType.fromString(id), 1, seqNo, primaryTerm);

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
    
    /*public static class DotPath {
        
        public static final DotPath ALL = new DotPath(null, "", null);
        private final String path;
        private String prepend;
        private String append;

        private DotPath(String prepend, String dotPath, String append) {
            super();
            this.path = dotPath;
            this.prepend = prepend;
            this.append = append;
        }

        public JsonPointer toJsonPointer() {

            String ptr = path;

            if(path.startsWith(".")) {
                throw new RuntimeException(path+" must not start with a dot");
            } else if(path.startsWith("/")) {
                throw new RuntimeException(path+" must not start with a slash");
            } else if(path.endsWith(".")) {
                throw new RuntimeException(path+" must not end with a dot");
            } else if(path.endsWith("/")) {
                throw new RuntimeException(path+" must not end with a slash");
            } else if(path.equals("")) {
                ptr = "";
            } else {
                //rfc6901 escaping
                ptr = "/"+path.replace("~", "~0").replace("/", "~1").replace('.', '/');
            } 
            
            if(append != null) {
                ptr += "/" + append.replace("~", "~0").replace("/", "~1");
            }
            
            if(prepend != null) {
                ptr = "/" + prepend.replace("~", "~0").replace("/", "~1")+ ptr;
            }

            return JsonPointer.compile(ptr);
        }

        public static DotPath of(String path) {
            return new DotPath(null, path, null);
        }
        
        public static DotPath of(String prepend, String path, String append) {
            return new DotPath(prepend, path, append);
        }

    }
    
    public static class MutableDynamicConfiguration implements ToXContent {
                
        private final ObjectNode objectNode;
        private final long seqNo;
        private final long primaryTerm;
        private final String type;
        
        public MutableDynamicConfiguration(JsonNode jsonNode, long seqNo, long primaryTerm, String type) {
            objectNode = (ObjectNode) jsonNode.deepCopy();
            this.seqNo = seqNo;
            this.primaryTerm = primaryTerm;
            this.type = type;
            
            
            
        }
        
        public DynamicConfiguration toDynamicConfiguration() {
            return new DynamicConfiguration(objectNode, seqNo, primaryTerm, type);
        }
        
        public void put(DotPath path, String key, String value) {
            JsonPointer ptr = path.toJsonPointer();
            JsonNode n = objectNode.at(ptr);
            if(n.isMissingNode()) {
                final ObjectNode tmp = JsonNodeFactory.instance.objectNode();
            } else {
               //String lastVal = ptr.last().toString();
               ((ObjectNode) objectNode.at(ptr)).put(key, value);
            }
        }

        public void put(String key, String value) {
            noDot(key);
            objectNode.put(key, value);
        }

        public long getSeqNo() {
            return seqNo;
        }

        public long getPrimaryTerm() {
            return primaryTerm;
        }

        public String getType() {
            return type;
        }

        public boolean containsKey(String name) {
            noDot(name);
            return objectNode.has(name);
        }

        public void put(String name, JsonNode node) {
            noDot(name);
            objectNode.set(name, node);
        }

        public void remove(String name) {
            noDot(name);
            objectNode.remove(name);
        }
        
        public Map<String, Object> getAsMap() {
            Map<String, Object> map = DefaultObjectMapper.objectMapper.convertValue(objectNode, typeRefMSO);
            return Collections.unmodifiableMap(map);
        }

        @Override
        public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
            builder.map(getAsMap());
            return builder;
        }
        
        private static void noDot(String val) {
            if(val!= null && val.contains(".")) {
                System.out.println("exception: no dot");
                new Exception().printStackTrace();
                throw new IllegalArgumentException();
            }
        }
        
        @Override
        public boolean isFragment() {
            return false;
        }
        
    }
    
    public static class DynamicConfiguration implements ToXContent{
                
        private final JsonNode jsonNode;
        private final long seqNo;
        private final long primaryTerm;
        private final String type;
        
        public DynamicConfiguration(JsonNode jsonNode, long seqNo, long primaryTerm, String type) {
            super();
            this.jsonNode = Objects.requireNonNull(jsonNode);
            this.seqNo = seqNo;
            this.primaryTerm = primaryTerm;
            this.type = type;
        }
        
        
        
        @Override
        public boolean isFragment() {
            return !(jsonNode instanceof ObjectNode);
        }



        public MutableDynamicConfiguration copyToMutable() {
            return new MutableDynamicConfiguration(jsonNode, seqNo, primaryTerm, type);
        }

        public static Function<String, String> checkKeyFunction() {
            return in -> {
                
                if(in != null && in.contains(".")) {
                    throw new RuntimeException("No dots allowed in keys ("+in+")");
                }
                
                return in;
            };
        }
        
        public String get(DotPath path, String defaultValue) {
            return jsonNode.at(path.toJsonPointer()).asText(defaultValue);
        }
        
        public String get(DotPath path) {
            return get(path, null);
        }

        public boolean getAsBoolean(DotPath path, boolean defaultVal) {
            return jsonNode.at(path.toJsonPointer()).asBoolean(defaultVal);
        }


        public List<String> getAsList(DotPath path, List<String> defaultList) {
           JsonNode n = jsonNode.at(path.toJsonPointer());
           
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


        public List<String> getAsList(DotPath path) {
            return getAsList(path, Collections.emptyList());
        }
        
        public DynamicConfiguration getByPrefix0(String parent) {
            final ObjectNode tmp = JsonNodeFactory.instance.objectNode();
            return new DynamicConfiguration(tmp.set(parent, jsonNode.get(parent)), seqNo, primaryTerm, type);
        }

        public DynamicConfiguration getByPrefix(DotPath path) {
            return new DynamicConfiguration(jsonNode.at(path.toJsonPointer()), seqNo, primaryTerm, type);
        }


        public Map<String, DynamicConfiguration> getGroups(DotPath path) {
            final Map<String, DynamicConfiguration> ret = new HashMap<>();
            final JsonNode node = jsonNode.at(path.toJsonPointer());
            for(String n: ImmutableSet.copyOf(node.fieldNames())) {
                ret.put(n, new DynamicConfiguration(node.get(n), seqNo, primaryTerm, type));
            }
            return Collections.unmodifiableMap(ret);
        }


        public boolean isEmpty() {
            return jsonNode.size() == 0;
        }


        public Set<String> names() {
           return ImmutableSet.copyOf(jsonNode.fieldNames());
        }

        @Override
        public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
            builder.map(getAsMap(DotPath.ALL));
            return builder;
        }


        public int getAsInt(DotPath path, int defaultVal) {
            return jsonNode.at(path.toJsonPointer()).asInt(defaultVal);
        }
        
        private Map<String, Object> getAsMap(DotPath path) {
            Map<String, Object> map = DefaultObjectMapper.objectMapper.convertValue(jsonNode.at(path.toJsonPointer()), typeRefMSO);
            return map==null?null:Collections.unmodifiableMap(map);
        }
        
        //TODO fails if children are objects/arrays
        public Map<String, String> getAsStringMap(DotPath path) {
            Map<String, String> map = DefaultObjectMapper.objectMapper.convertValue(jsonNode.at(path.toJsonPointer()), typeRefMSS);
            return map==null?Collections.emptyMap():Collections.unmodifiableMap(map);
        }

        @Override
        public String toString() {
            try {
                return "DynamicConfiguration [jsonNode=" + DefaultObjectMapper.objectMapper.writeValueAsString(jsonNode) + ", seqNo=" + seqNo + ", primaryTerm=" + primaryTerm + ", type=" + type + "]";
            } catch (JsonProcessingException e) {
                e.printStackTrace();
                return e.getMessage();
            }
        }


        public long getSeqNo() {
            return seqNo;
        }


        public long getPrimaryTerm() {
            return primaryTerm;
        }


        public String getType() {
            return type;
        }
        
        
    }
    
    */
}
