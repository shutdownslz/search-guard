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

package com.floragunn.searchguard.support;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamClass;
import java.io.Serializable;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.common.io.stream.InputStreamStreamInput;
import org.elasticsearch.common.io.stream.OutputStreamStreamOutput;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.io.stream.Writeable;
import org.elasticsearch.common.io.stream.Writeable.Reader;
import org.elasticsearch.common.io.stream.Writeable.Writer;
import org.elasticsearch.common.transport.TransportAddress;

import com.floragunn.searchguard.configuration.ClusterInfoHolder;
import com.floragunn.searchguard.user.User;
import com.google.common.io.BaseEncoding;

public class SerializationHelper {
    
    private final ClusterInfoHolder cih;

    public SerializationHelper(final ClusterInfoHolder cih) {
        super();
        this.cih = cih;
    }

    public String serializeTransportAddress(final TransportAddress address) {
        if(legacy0()) {
            return serializeObject0(address.address());
        } else {
            return "#"+serializeWriteable0(address);
        }
    }
    
    private boolean legacy0() {
        return cih.getHas5xNodes() != Boolean.FALSE;
    }

    public String serializeUser(final User user) {
        if(legacy0()) {
            return serializeObject0(user);
        } else {
            return "#"+serializeWriteable0(user);
        }
    }
    
    public String serializeMap(final Map<String, Set<String>> map) {
        if(legacy0()) {
            return serializeObject0((Serializable) map);
        } else {
            return "#"+serializeWriteable0(map);
        }
    }

    public TransportAddress deserializeTransportAddress(final String string) {
        if(string.charAt(0) != '#') {
            return new TransportAddress((InetSocketAddress) deserializeObject0(string));
        } else {
            return deserializeTransportAddress0(string.substring(1));
        }
    }
    
    public User deserializeUser(final String string) {
        if(string.charAt(0) != '#') {
            return (User) deserializeObject0(string);
        } else {
            return deserializeUser0(string.substring(1));
        }
    }
    
    public Map<String, Set<String>> deserializeMap(final String map) {
        if(map.charAt(0) != '#') {
            return (Map<String, Set<String>>) deserializeObject0(map);
        } else {
            return (Map<String, Set<String>>) deserializeMap0(map.substring(1));
        }
    }
    
    private static String serializeWriteable0(final Object object) {

        if (object == null) {
            throw new IllegalArgumentException("object must not be null");
        }

        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            final StreamOutput so = new OutputStreamStreamOutput(bos);
            if(object instanceof Writeable) {
                ((Writeable) object).writeTo(so);
            } else {
                Map<String, Set<String>> map = (Map<String, Set<String>>) object;
                so.writeMap(map, StreamOutput::writeString, STRING_SET_WRITER::write);
            }
            //so.flush();
            return BaseEncoding.base64().encode(bos.toByteArray());
        } catch (final Exception e) {
            e.printStackTrace();
            throw new ElasticsearchException(e.toString());
        }
    }
    
    private static final StringSetWriter STRING_SET_WRITER = new StringSetWriter();
    
    private static class StringSetWriter implements Writer<Set<String>> {

        @Override
        public void write(final StreamOutput out, final Set<String> value) throws IOException {
            out.writeStringList(new ArrayList<String>(value));
        }
    }
    
    private static final StringSetReader STRING_SET_READER = new StringSetReader();
    
    private static class StringSetReader implements Reader<Set<String>> {

        @Override
        public Set<String> read(final StreamInput in) throws IOException {
            return new HashSet<String>(in.readList(StreamInput::readString));
        }
    }
    
    private static User deserializeUser0(final String string) {
        if (string == null) {
            throw new IllegalArgumentException("string must not be null");
        }

        try {
            final byte[] userr = BaseEncoding.base64().decode(string);
            final ByteArrayInputStream bis = new ByteArrayInputStream(userr); //NOSONAR
            final StreamInput si = new InputStreamStreamInput(bis);
            return new User(si);
        } catch (final Exception e) {
            e.printStackTrace();
            throw new ElasticsearchException(e);
        }
    }
    
    private static TransportAddress deserializeTransportAddress0(final String string) {
        if (string == null) {
            throw new IllegalArgumentException("string must not be null");
        }

        try {
            final byte[] userr = BaseEncoding.base64().decode(string);
            final ByteArrayInputStream bis = new ByteArrayInputStream(userr); //NOSONAR
            final StreamInput si = new InputStreamStreamInput(bis);
            return new TransportAddress(si);
        } catch (final Exception e) {
            e.printStackTrace();
            throw new ElasticsearchException(e);
        }
    }
    
    private static Map<String, Set<String>> deserializeMap0(final String string) {
        if (string == null) {
            throw new IllegalArgumentException("string must not be null");
        }

        try {
            final byte[] userr = BaseEncoding.base64().decode(string);
            final ByteArrayInputStream bis = new ByteArrayInputStream(userr); //NOSONAR
            final StreamInput si = new InputStreamStreamInput(bis);
            return si.readMap(StreamInput::readString, STRING_SET_READER::read);
        } catch (final Exception e) {
            e.printStackTrace();
            throw new ElasticsearchException(e);
        }
    }
    
    private static String serializeObject0(final Serializable object) {

        if (object == null) {
            throw new IllegalArgumentException("object must not be null");
        }

        try {
            final ByteArrayOutputStream bos = new ByteArrayOutputStream();
            final ObjectOutputStream out = new ObjectOutputStream(bos);
            out.writeObject(object);
            final byte[] bytes = bos.toByteArray();
            return BaseEncoding.base64().encode(bytes);
        } catch (final Exception e) {
            throw new ElasticsearchException(e.toString());
        }
    }

    private static Serializable deserializeObject0(final String string) {

        if (string == null) {
            throw new IllegalArgumentException("string must not be null");
        }

        SafeObjectInputStream in = null;

        try {
            final byte[] userr = BaseEncoding.base64().decode(string);
            final ByteArrayInputStream bis = new ByteArrayInputStream(userr); //NOSONAR
            in = new SafeObjectInputStream(bis); //NOSONAR
            return (Serializable) in.readObject();
        } catch (final Exception e) {
            throw new ElasticsearchException(e);
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException e) {
                    // ignore
                }
            }
        }
    }
    
    private final static class SafeObjectInputStream extends ObjectInputStream {

        private static final List<String> SAFE_CLASSES = new ArrayList<>();

        static {
            SAFE_CLASSES.add("com.floragunn.dlic.auth.ldap.LdapUser");
            SAFE_CLASSES.add("org.ldaptive.SearchEntry");
            SAFE_CLASSES.add("org.ldaptive.LdapEntry");
            SAFE_CLASSES.add("org.ldaptive.AbstractLdapBean");
            SAFE_CLASSES.add("org.ldaptive.LdapAttribute");
            SAFE_CLASSES.add("org.ldaptive.LdapAttribute$LdapAttributeValues");
        }

        public SafeObjectInputStream(InputStream in) throws IOException {
            super(in);
        }

        @Override
        protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {

            Class<?> clazz = super.resolveClass(desc);

            if (
                    clazz.isArray() ||
                    clazz.equals(String.class) ||
                    clazz.equals(SocketAddress.class) ||
                    clazz.equals(InetSocketAddress.class) ||
                    InetAddress.class.isAssignableFrom(clazz) ||
                    Number.class.isAssignableFrom(clazz) ||
                    Collection.class.isAssignableFrom(clazz) ||
                    Map.class.isAssignableFrom(clazz) ||
                    Enum.class.isAssignableFrom(clazz) ||
                    clazz.equals(User.class) ||
                    SAFE_CLASSES.contains(clazz.getName())
               ) {

                return clazz;
            }

            throw new InvalidClassException("Unauthorized deserialization attempt", clazz.getName());
        }
    }
}
