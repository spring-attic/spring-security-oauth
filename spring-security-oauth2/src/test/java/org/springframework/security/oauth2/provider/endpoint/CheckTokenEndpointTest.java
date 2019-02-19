/*
 * Copyright 2012-2019 the original author or authors.
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
import org.springframework.security.oauth2.provider.token.AccessTokenConverter;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * @author Joe Grandja
 */
public class CheckTokenEndpointTest {
	private CheckTokenEndpoint checkTokenEndpoint;
	private AccessTokenConverter accessTokenConverter;

	@Before
	public void setUp() {
		OAuth2AccessToken accessToken = mock(OAuth2AccessToken.class);
		when(accessToken.isExpired()).thenReturn(false);
		ResourceServerTokenServices resourceServerTokenServices = mock(ResourceServerTokenServices.class);
		when(resourceServerTokenServices.readAccessToken(anyString())).thenReturn(accessToken);
		this.checkTokenEndpoint = new CheckTokenEndpoint(resourceServerTokenServices);
		this.accessTokenConverter = mock(AccessTokenConverter.class);
		when(this.accessTokenConverter.convertAccessToken(any(OAuth2AccessToken.class), any(OAuth2Authentication.class))).thenReturn(new HashMap());
		this.checkTokenEndpoint.setAccessTokenConverter(new CheckTokenEndpoint.CheckTokenAccessTokenConverter(this.accessTokenConverter));
	}

	// gh-1070
	@Test
	public void checkTokenWhenDefaultAccessTokenConverterThenActiveAttributeReturned() throws Exception {
		Map<String, ?> response = this.checkTokenEndpoint.checkToken("access-token-1234");
		Object active = response.get("active");
		assertNotNull("active is null", active);
		assertEquals("active not true", Boolean.TRUE, active);
	}

	// gh-1591
	@Test
	public void checkTokenWhenCustomAccessTokenConverterThenActiveAttributeNotReturned() throws Exception {
		this.accessTokenConverter = mock(AccessTokenConverter.class);
		when(this.accessTokenConverter.convertAccessToken(any(OAuth2AccessToken.class), any(OAuth2Authentication.class))).thenReturn(new HashMap());
		this.checkTokenEndpoint.setAccessTokenConverter(this.accessTokenConverter);
		Map<String, ?> response = this.checkTokenEndpoint.checkToken("access-token-1234");
		assertNull("active is not null", response.get("active"));
	}
}