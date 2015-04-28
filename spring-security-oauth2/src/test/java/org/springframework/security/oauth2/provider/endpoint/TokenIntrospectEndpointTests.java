/*
 * Copyright 2002-2011 the original author or authors.
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
package org.springframework.security.oauth2.provider.endpoint;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.web.HttpRequestMethodNotSupportedException;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.*;

import java.util.Map;
import java.util.UUID;

/**
 * @author Jeff Beck
 */
public class TokenIntrospectEndpointTests {

	private ResourceServerTokenServices resourceServerTokenServices;

	private TokenIntrospectEndpoint endpoint;

	@Before
	public void init() {

		resourceServerTokenServices = mock(ResourceServerTokenServices.class);
		endpoint = new TokenIntrospectEndpoint(resourceServerTokenServices);

	}

	@Test
	public void testIntrospectValidToken() throws HttpRequestMethodNotSupportedException {
		OAuth2Authentication oAuth2Authentication = mock(OAuth2Authentication.class);
		OAuth2AccessToken oAuth2AccessToken = mock(OAuth2AccessToken.class);
		OAuth2Request oAuth2Request = mock(OAuth2Request.class);

		String uuid = UUID.randomUUID().toString();

		when(oAuth2Authentication.getOAuth2Request()).thenReturn(oAuth2Request);
		when(oAuth2Authentication.isAuthenticated()).thenReturn(true);
		when(oAuth2Authentication.isClientOnly()).thenReturn(true);
		when(oAuth2AccessToken.isExpired()).thenReturn(false);
		when(oAuth2AccessToken.getValue()).thenReturn(uuid);

		when(resourceServerTokenServices.readAccessToken(uuid)).thenReturn(oAuth2AccessToken);
		when(resourceServerTokenServices.loadAuthentication(uuid)).thenReturn(oAuth2Authentication);

		Map<String, ?> response = endpoint.introspectToken(uuid, null, null);

		assertEquals(response.get("active"), true);
	}

	@Test
	public void testIntrospectInvalidToken() throws HttpRequestMethodNotSupportedException {
		String uuid = UUID.randomUUID().toString();

		Map<String, ?> response = endpoint.introspectToken(uuid, null, null);

		verify(resourceServerTokenServices).readAccessToken(uuid);
		verifyNoMoreInteractions(resourceServerTokenServices);

		assertEquals(response.get("active"), false);
	}

	@Test
	public void testIntrospectExpiredToken() throws HttpRequestMethodNotSupportedException {
		OAuth2AccessToken oAuth2AccessToken = mock(OAuth2AccessToken.class);

		String uuid = UUID.randomUUID().toString();

		when(oAuth2AccessToken.isExpired()).thenReturn(true);
		when(resourceServerTokenServices.readAccessToken(uuid)).thenReturn(oAuth2AccessToken);

		Map<String, ?> response = endpoint.introspectToken(uuid, null, null);

		assertEquals(response.get("active"), false);
	}

}
