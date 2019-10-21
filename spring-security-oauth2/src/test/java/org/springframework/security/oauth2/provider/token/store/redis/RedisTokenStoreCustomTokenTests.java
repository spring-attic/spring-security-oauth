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

package org.springframework.security.oauth2.provider.token.store.redis;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

import org.company.oauth2.CustomOAuth2AccessToken;
import org.company.oauth2.CustomOAuth2Authentication;
import org.junit.Before;
import org.junit.Test;
import org.springframework.core.serializer.support.SerializationFailedException;
import org.springframework.data.redis.connection.jedis.JedisConnectionFactory;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.util.SerializationStrategy;
import org.springframework.security.oauth2.common.util.SerializationUtils;
import org.springframework.security.oauth2.common.util.WhitelistedSerializationStrategy;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.RequestTokenFactory;
import org.springframework.util.ClassUtils;
import redis.clients.jedis.JedisShardInfo;

import static org.junit.Assert.*;

/**
 * @author Artem Smotrakov
 */
public class RedisTokenStoreCustomTokenTests {

    private static final String CLIENT_ID = "customClient";

    private static final List<String> ALLOWED_CLASSES = new ArrayList<String>();

    static {
        ALLOWED_CLASSES.add("java.util.");
        ALLOWED_CLASSES.add("org.springframework.security.");
        ALLOWED_CLASSES.add("org.company.oauth2.CustomOAuth2AccessToken");
        ALLOWED_CLASSES.add("org.company.oauth2.CustomOAuth2Authentication");
    }

    private RedisTokenStore tokenStore;

    @Before
    public void setup() {
        boolean springDataRedis_2_0 = ClassUtils.isPresent(
                "org.springframework.data.redis.connection.RedisStandaloneConfiguration",
                this.getClass().getClassLoader());

        JedisConnectionFactory connectionFactory;
        if (springDataRedis_2_0) {
            connectionFactory = new JedisConnectionFactory();
        } else {
            JedisShardInfo shardInfo = new JedisShardInfo("localhost");
            connectionFactory = new JedisConnectionFactory(shardInfo);
        }

        tokenStore = new RedisTokenStore(connectionFactory);
    }

    @Test
    public void testCustomToken() {
        OAuth2Request request = RequestTokenFactory.createOAuth2Request(CLIENT_ID, false);
        TestingAuthenticationToken authentication = new TestingAuthenticationToken("user", "password");

        String token = "access-token-" + UUID.randomUUID();
        OAuth2AccessToken oauth2AccessToken = new CustomOAuth2AccessToken(token);
        OAuth2Authentication oauth2Authentication = new OAuth2Authentication(request, authentication);

        tokenStore.storeAccessToken(oauth2AccessToken, oauth2Authentication);
        Collection<OAuth2AccessToken> tokens = tokenStore.findTokensByClientId(request.getClientId());
        assertNotNull(tokens);
        assertFalse(tokens.isEmpty());
        for (OAuth2AccessToken oAuth2AccessToken : tokens) {
            if (token.equals(oAuth2AccessToken.getValue())) {
                return;
            }
        }
        fail("No token found!");
    }

    @Test(expected = SerializationFailedException.class)
    public void testNotAllowedCustomToken() {
        OAuth2Request request = RequestTokenFactory.createOAuth2Request(CLIENT_ID, false);
        TestingAuthenticationToken authentication = new TestingAuthenticationToken("user", "password");

        String token = "access-token-" + UUID.randomUUID();
        OAuth2AccessToken oauth2AccessToken = new CustomOAuth2AccessToken(token);
        OAuth2Authentication oauth2Authentication = new OAuth2Authentication(request, authentication);

        WhitelistedSerializationStrategy newStrategy = new WhitelistedSerializationStrategy();
        SerializationStrategy oldStrategy = SerializationUtils.getSerializationStrategy();
        try {
            SerializationUtils.setSerializationStrategy(newStrategy);
            tokenStore.storeAccessToken(oauth2AccessToken, oauth2Authentication);
            tokenStore.findTokensByClientId(request.getClientId());
        } finally {
            SerializationUtils.setSerializationStrategy(oldStrategy);
        }
    }

    @Test
    public void testCustomTokenWithCustomSerializationStrategy() {
        OAuth2Request request = RequestTokenFactory.createOAuth2Request(CLIENT_ID, false);
        TestingAuthenticationToken authentication = new TestingAuthenticationToken("user", "password");

        OAuth2AccessToken oauth2AccessToken = new CustomOAuth2AccessToken("access-token-" + UUID.randomUUID());
        OAuth2Authentication oauth2Authentication = new CustomOAuth2Authentication(request, authentication);

        WhitelistedSerializationStrategy newStrategy = new WhitelistedSerializationStrategy(ALLOWED_CLASSES);
        SerializationStrategy oldStrategy = SerializationUtils.getSerializationStrategy();
        try {
            SerializationUtils.setSerializationStrategy(newStrategy);
            tokenStore.storeAccessToken(oauth2AccessToken, oauth2Authentication);

            OAuth2AccessToken token = tokenStore.getAccessToken(oauth2Authentication);
            assertNotNull(token);
            assertEquals(oauth2AccessToken, token);
        } finally {
            SerializationUtils.setSerializationStrategy(oldStrategy);
        }
    }

}