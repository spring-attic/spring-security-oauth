/*
 * Copyright 2012-2019 the original author or authors.
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

package org.springframework.security.oauth2.common.util;


import org.company.oauth2.CustomAuthentication;
import org.company.oauth2.CustomOAuth2AccessToken;
import org.company.oauth2.CustomOAuth2Authentication;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.springframework.core.io.support.SpringFactoriesLoader;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.common.DefaultExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.RequestTokenFactory;

import java.io.Serializable;
import java.util.*;

import static org.junit.Assert.*;
import static org.powermock.api.mockito.PowerMockito.spy;
import static org.powermock.api.mockito.PowerMockito.when;

@RunWith(PowerMockRunner.class)
@PrepareForTest({ SpringFactoriesLoader.class })
public class CustomSerializationStrategyTests {

    @Test
    public void loadCustomSerializationStrategy() {
        spy(SpringFactoriesLoader.class);
        when(SpringFactoriesLoader
                .loadFactories(SerializationStrategy.class, SerializationUtils.class.getClassLoader()))
                .thenReturn(Arrays.<SerializationStrategy>asList(new CustomSerializationStrategy()));

        deserialize(new DefaultOAuth2AccessToken("access-token-" + UUID.randomUUID()));

        deserialize(new OAuth2Authentication(
                new OAuth2Request(Collections.<String, String>emptyMap(), "clientId", Collections.<GrantedAuthority>emptyList(),
                        false, Collections.<String>emptySet(),
                        new HashSet<String>(Arrays.asList("resourceId-1", "resourceId-2")), "redirectUri",
                        Collections.<String>emptySet(), Collections.<String, Serializable>emptyMap()),
                new UsernamePasswordAuthenticationToken("test", "N/A")));

        deserialize(new DefaultExpiringOAuth2RefreshToken(
                "access-token-" + UUID.randomUUID(), new Date()));

        deserialize("xyz");
        deserialize(new HashMap<String, String>());

        deserialize(new CustomOAuth2AccessToken("xyz"));

        deserialize(
                new CustomOAuth2Authentication(
                        RequestTokenFactory.createOAuth2Request("id", false),
                        new CustomAuthentication("test", false)));
    }

    private void deserialize(Object object) {
        byte[] bytes = SerializationUtils.serialize(object);
        assertNotNull(bytes);
        assertTrue(bytes.length > 0);

        Object clone = SerializationUtils.deserialize(bytes);
        assertNotNull(clone);
        assertEquals(object, clone);
    }

    private static class CustomSerializationStrategy extends WhitelistedSerializationStrategy {

        private static final List<String> ALLOWED_CLASSES = new ArrayList<String>();
        static {
            ALLOWED_CLASSES.add("java.lang.");
            ALLOWED_CLASSES.add("java.util.");
            ALLOWED_CLASSES.add("org.springframework.security.");
            ALLOWED_CLASSES.add("org.company.oauth2.");
        }

        CustomSerializationStrategy() {
            super(ALLOWED_CLASSES);
        }

    }

}
