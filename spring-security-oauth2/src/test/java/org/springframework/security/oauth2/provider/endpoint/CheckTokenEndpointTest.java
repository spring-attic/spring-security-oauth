/*
 * Copyright 2012-2017 the original author or authors.
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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * @author Joe Grandja
 */
public class CheckTokenEndpointTest {
	private CheckTokenEndpoint checkTokenEndpoint;

	@Before
	public void setUp() {
		ResourceServerTokenServices resourceServerTokenServices = mock(ResourceServerTokenServices.class);
		OAuth2AccessToken accessToken = mock(OAuth2AccessToken.class);
		OAuth2Authentication authentication = mock(OAuth2Authentication.class);
		when(resourceServerTokenServices.readAccessToken(anyString())).thenReturn(accessToken);
		when(accessToken.isExpired()).thenReturn(false);
		when(accessToken.getValue()).thenReturn("access-token-1234");
		when(resourceServerTokenServices.loadAuthentication(accessToken.getValue())).thenReturn(authentication);
		this.checkTokenEndpoint = new CheckTokenEndpoint(resourceServerTokenServices);

		AccessTokenConverter accessTokenConverter = mock(AccessTokenConverter.class);
		when(accessTokenConverter.convertAccessToken(accessToken, authentication)).thenReturn(new HashMap());
		this.checkTokenEndpoint.setAccessTokenConverter(accessTokenConverter);
	}

	// gh-1070
	@Test
	public void checkTokenWhenTokenValidThenReturnActiveAttribute() throws Exception {
		Map<String, ?> response = this.checkTokenEndpoint.checkToken("access-token-1234");
		Object active = response.get("active");
		assertNotNull("active is null", active);
		assertEquals("active not true", Boolean.TRUE, active);
	}
}