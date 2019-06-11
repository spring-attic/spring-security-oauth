/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.provider.token.store.redis;

import org.junit.Test;
import org.springframework.core.serializer.support.SerializationFailedException;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.HashMap;
import java.util.UUID;

import static org.junit.Assert.*;

/**
 * @author Artem Smotrakov
 */
public class JdkSerializationStrategyTests {
    private JdkSerializationStrategy serializationStrategy = new JdkSerializationStrategy();

    @Test
    public void deserializeAllowedClasses() {
        deserializeAllowedClasses(new DefaultOAuth2AccessToken("access-token-" + UUID.randomUUID()));
        deserializeAllowedClasses("xyz");
        deserializeAllowedClasses(new HashMap<String, String>());
    }

    private void deserializeAllowedClasses(Object object) {
        byte[] bytes = this.serializationStrategy.serialize(object);
        Object clone = this.serializationStrategy.deserialize(bytes, Object.class);
        assertEquals(object, clone);
    }

    @Test(expected = SerializationFailedException.class)
    public void deserializeProhibitedClasses() throws UnknownHostException {
        byte[] bytes = this.serializationStrategy.serializeInternal(InetAddress.getLocalHost());
        this.serializationStrategy.deserializeInternal(bytes, Object.class);
    }

    @Test
    public void deserializeEmpty() {
        assertNull(this.serializationStrategy.deserialize(null, Object.class));
        assertNull(this.serializationStrategy.deserialize(new byte[0], Object.class));
    }

    @Test
    public void serializeNull() {
        assertArrayEquals(new byte[0], this.serializationStrategy.serialize(null));
    }
}
