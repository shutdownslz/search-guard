package com.floragunn.searchguard.configuration;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.common.xcontent.ToXContent;
import org.elasticsearch.common.xcontent.XContentBuilder;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.floragunn.searchguard.DefaultObjectMapper;

public class SgDynamicConfiguration<T> implements ToXContent {
    
    private static final TypeReference<HashMap<String,Object>> typeRefMSO = new TypeReference<HashMap<String,Object>>() {};

    private long seqNo= -1;
    private long primaryTerm= -1;
    private CType ctype;
    private int version;

    public static <T> SgDynamicConfiguration<T> fromJson(String json, CType ctype, int version, long seqNo, long primaryTerm) throws IOException {
        SgDynamicConfiguration<T> sdc = DefaultObjectMapper.readValue(json, DefaultObjectMapper.getTypeFactory().constructParametricType(SgDynamicConfiguration.class, ctype.getImplementationClass().get(version)));
        sdc.ctype = ctype;
        sdc.seqNo = seqNo;
        sdc.primaryTerm = primaryTerm;
        sdc.version = version;
        return sdc;
    }
    
    public static <T> SgDynamicConfiguration<T> fromNode(JsonNode json, CType ctype, int version, long seqNo, long primaryTerm) throws IOException {
        return fromJson(DefaultObjectMapper.writeValueAsString(json, false), ctype, version, seqNo, primaryTerm);
    }
    
    public SgDynamicConfiguration() {
        super();
    }

    @JsonIgnore
    private final Map<String, T> centries = new HashMap<>();
    
    @JsonAnySetter
    void setCEntries(String key, T value) {
        putCEntry(key, value);
    }
    
    @JsonAnyGetter
    public Map<String, T> getCEntries() {
        return centries;
    }
    
    @JsonIgnore
    public void removeHidden() {
        for(Entry<String, T> entry: new HashMap<String, T>(centries).entrySet()) {
            if(entry.getValue() instanceof Hideable && ((Hideable) entry.getValue()).isHidden()) {
                centries.remove(entry.getKey());
            }
        }
    }
    
    @JsonIgnore
    public void clearHashes() {
        for(Entry<String, T> entry: centries.entrySet()) {
            if(entry.getValue() instanceof Hashed) {
               ((Hashed) entry.getValue()).clearHash(); 
            }
        }
    }
    
    @JsonIgnore
    public SgDynamicConfiguration<T> getCEntryFull(String key) {
        SgDynamicConfiguration<T> clone = this.deepClone();
        T tmp = clone.centries.get(key);
        clone.centries.clear();
        clone.centries.put(key, tmp);
        return clone;
    }
    
    @JsonIgnore
    public T putCEntry(String key, T value) {
        return centries.put(key, value);
    }
    
    @JsonIgnore
    public void putCObject(String key, Object value) {
        centries.put(key, (T) value);
    }
    
    @JsonIgnore
    public T getCEntry(String key) {
        return centries.get(key);
    }
    
    @JsonIgnore
    public boolean exists(String key) {
        return centries.containsKey(key);
    }

    

    @Override
    public String toString() {
        return "SgDynamicConfiguration [seqNo=" + seqNo + ", primaryTerm=" + primaryTerm + ", ctype=" + ctype + ", version=" + version + ", centries="
                + centries + ", getImplementingClass()=" + getImplementingClass() + "]";
    }

    @Override
    @JsonIgnore
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        final boolean omitDefaults = params != null && params.paramAsBoolean("omit_defaults", false);
        return builder.map(DefaultObjectMapper.readValue(DefaultObjectMapper.writeValueAsString(this, omitDefaults), typeRefMSO));
    }
    
    @Override
    @JsonIgnore
    public boolean isFragment() {
        return false;
    }

    @JsonIgnore
    public long getSeqNo() {
        return seqNo;
    }

    @JsonIgnore
    public long getPrimaryTerm() {
        return primaryTerm;
    }

    @JsonIgnore
    public CType getCType() {
        return ctype;
    }

    @JsonIgnore
    public int getVersion() {
        return version;
    }
    
    @JsonIgnore
    public Class getImplementingClass() {
        return ctype.getImplementationClass().get(getVersion());
    }

    @JsonIgnore
    public SgDynamicConfiguration<T> deepClone() {
        try {
            return fromJson(DefaultObjectMapper.writeValueAsString(this, false), ctype, version, seqNo, primaryTerm);
        } catch (Exception e) {
            throw ExceptionsHelper.convertToElastic(e);
        }
    }

    @JsonIgnore
    public void remove(String key) {
       centries.remove(key);
        
    }
    
}