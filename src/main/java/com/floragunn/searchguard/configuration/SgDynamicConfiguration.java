package com.floragunn.searchguard.configuration;

import java.io.File;
import java.io.IOException;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.Map;

import org.elasticsearch.common.Strings;
import org.elasticsearch.common.xcontent.ToXContent;
import org.elasticsearch.common.xcontent.XContentBuilder;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.core.type.TypeReference;
import com.floragunn.searchguard.DefaultObjectMapper;

public class SgDynamicConfiguration<T> implements ToXContent {
    
    private static final TypeReference<HashMap<String,Object>> typeRefMSO = new TypeReference<HashMap<String,Object>>() {};

    private long seqNo= -1;
    private long primaryTerm= -1;
    
    private CType ctype;

    public static <T> SgDynamicConfiguration<T> fromJson(String json, CType ctype, int version, long seqNo, long primaryTerm) throws IOException {
        SgDynamicConfiguration<T> sdc = DefaultObjectMapper.objectMapperYaml.readValue(json, DefaultObjectMapper.objectMapperYaml.getTypeFactory().constructParametricType(SgDynamicConfiguration.class, ctype.getImplementationClass().get(version)));
        sdc.ctype = ctype;
        sdc.seqNo = seqNo;
        sdc.primaryTerm = primaryTerm;
        return sdc;
    }
    
    public static <T> SgDynamicConfiguration<T> parseYmlFile(File json, CType ctype, int version, long seqNo, long primaryTerm) throws IOException {
        SgDynamicConfiguration<T> sdc = DefaultObjectMapper.objectMapperYaml.readValue(json, DefaultObjectMapper.objectMapperYaml.getTypeFactory().constructParametricType(SgDynamicConfiguration.class, ctype.getImplementationClass().get(version)));
        sdc.ctype = ctype;
        sdc.seqNo = seqNo;
        sdc.primaryTerm = primaryTerm;
        return sdc;
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
    
    public T putCEntry(String key, T value) {
        return centries.put(key, value);
    }
    
    public T getCEntry(String key) {
        return centries.get(key);
    }
    
    public boolean exists(String key) {
        return centries.containsKey(key);
    }

    @Override
    public String toString() {
        return "SgDynamicConfiguration [seqNo=" + seqNo + ", primaryTerm=" + primaryTerm + ", ctype=" + ctype + ", centries=" + centries + "]";
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        StringWriter sw = new StringWriter();
        DefaultObjectMapper.objectMapper.writeValue(sw, this);
        return builder.map(DefaultObjectMapper.objectMapper.readValue(sw.toString(), typeRefMSO));
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
    
}