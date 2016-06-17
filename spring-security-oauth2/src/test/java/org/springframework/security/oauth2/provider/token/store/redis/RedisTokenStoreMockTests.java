/*
 * Copyright 2012-2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.provider.token.store.redis;

import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.data.redis.connection.jedis.JedisConnection;
import org.springframework.data.redis.connection.jedis.JedisConnectionFactory;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.DefaultOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.RequestTokenFactory;

import java.util.*;

import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;

/**
 *
 * @author Joe Grandja
 *
 */
public class RedisTokenStoreMockTests {
	private JedisConnectionFactory connectionFactory;
	private JedisConnection connection;
	private RedisTokenStore tokenStore;
	private OAuth2Request request;
	private TestingAuthenticationToken authentication;

	@Before
	public void setUp() throws Exception {
		connectionFactory = mock(JedisConnectionFactory.class);
		connection = mock(JedisConnection.class);
		when(connectionFactory.getConnection()).thenReturn(connection);
		tokenStore = new RedisTokenStore(connectionFactory);
		Set<String> scope = new LinkedHashSet<String>(Arrays.asList("read", "write", "read-write"));
		request = RequestTokenFactory.createOAuth2Request("clientId", false, scope);
		authentication = new TestingAuthenticationToken("user", "password");
	}

	// gh-572
	@Test
	public void storeRefreshTokenRemoveRefreshTokenVerifyKeysRemoved() {
		OAuth2RefreshToken oauth2RefreshToken = new DefaultOAuth2RefreshToken("refresh-token-" + UUID.randomUUID());
		OAuth2Authentication oauth2Authentication = new OAuth2Authentication(request, authentication);
		tokenStore.storeRefreshToken(oauth2RefreshToken, oauth2Authentication);

		ArgumentCaptor<byte[]> keyArgs = ArgumentCaptor.forClass(byte[].class);
		verify(connection, times(2)).set(keyArgs.capture(), any(byte[].class));

		tokenStore.removeRefreshToken(oauth2RefreshToken);

		for (byte[] key : keyArgs.getAllValues()) {
			verify(connection).del(key);
		}
	}

	// gh-572
	@Test
	public void storeAccessTokenWithoutRefreshTokenRemoveAccessTokenVerifyKeysRemoved() {
		OAuth2AccessToken oauth2AccessToken = new DefaultOAuth2AccessToken("access-token-" + UUID.randomUUID());
		OAuth2Authentication oauth2Authentication = new OAuth2Authentication(request, authentication);

		List<Object> results = Arrays.<Object>asList("access-token".getBytes(), "authentication".getBytes());
		when(connection.closePipeline()).thenReturn(results);

		RedisTokenStoreSerializationStrategy serializationStrategy = new JdkSerializationStrategy();
		serializationStrategy = spy(serializationStrategy);
		when(serializationStrategy.deserialize(any(byte[].class), eq(OAuth2Authentication.class))).thenReturn(oauth2Authentication);
		tokenStore.setSerializationStrategy(serializationStrategy);

		tokenStore.storeAccessToken(oauth2AccessToken, oauth2Authentication);

		ArgumentCaptor<byte[]> setKeyArgs = ArgumentCaptor.forClass(byte[].class);
		verify(connection, times(3)).set(setKeyArgs.capture(), any(byte[].class));

		ArgumentCaptor<byte[]> rPushKeyArgs = ArgumentCaptor.forClass(byte[].class);
		verify(connection, times(2)).rPush(rPushKeyArgs.capture(), any(byte[].class));

		tokenStore.removeAccessToken(oauth2AccessToken);

		for (byte[] key : setKeyArgs.getAllValues()) {
			verify(connection).del(key);
		}
		for (byte[] key : rPushKeyArgs.getAllValues()) {
			verify(connection).lRem(eq(key), eq(1L), any(byte[].class));
		}
	}

}