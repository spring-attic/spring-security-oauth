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
package org.springframework.security.oauth2.provider.token;

import org.junit.Before;
import org.junit.Test;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertNotNull;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * @author Joe Grandja
 */
public class RemoteTokenServicesTest {
	private static final String DEFAULT_CLIENT_ID = "client-id-1234";
	private static final String DEFAULT_CLIENT_SECRET = "client-secret-1234";
	private static final String DEFAULT_CHECK_TOKEN_ENDPOINT_URI = "/oauth/check_token";
	private RemoteTokenServices remoteTokenServices;

	@Before
	public void setUp() {
		this.remoteTokenServices = new RemoteTokenServices();
		this.remoteTokenServices.setClientId(DEFAULT_CLIENT_ID);
		this.remoteTokenServices.setClientSecret(DEFAULT_CLIENT_SECRET);
		this.remoteTokenServices.setCheckTokenEndpointUrl(DEFAULT_CHECK_TOKEN_ENDPOINT_URI);
	}

	// gh-838
	@Test
	public void loadAuthenticationWhenIntrospectionResponseContainsActiveTrueThenReturnAuthentication() throws Exception {
		Map responseAttrs = new HashMap();
		responseAttrs.put("active", true);		// "active" is the only required attribute as per RFC 7662 (https://tools.ietf.org/search/rfc7662#section-2.2)
		ResponseEntity<Map> response = new ResponseEntity<Map>(responseAttrs, HttpStatus.OK);
		RestTemplate restTemplate = mock(RestTemplate.class);
		when(restTemplate.exchange(anyString(), any(HttpMethod.class), any(HttpEntity.class), any(Class.class))).thenReturn(response);
		this.remoteTokenServices.setRestTemplate(restTemplate);

		OAuth2Authentication authentication = this.remoteTokenServices.loadAuthentication("access-token-1234");
		assertNotNull(authentication);
	}

	// gh-838
	@Test(expected = InvalidTokenException.class)
	public void loadAuthenticationWhenIntrospectionResponseContainsActiveFalseThenThrowInvalidTokenException() throws Exception {
		Map responseAttrs = new HashMap();
		responseAttrs.put("active", false);		// "active" is the only required attribute as per RFC 7662 (https://tools.ietf.org/search/rfc7662#section-2.2)
		ResponseEntity<Map> response = new ResponseEntity<Map>(responseAttrs, HttpStatus.OK);
		RestTemplate restTemplate = mock(RestTemplate.class);
		when(restTemplate.exchange(anyString(), any(HttpMethod.class), any(HttpEntity.class), any(Class.class))).thenReturn(response);
		this.remoteTokenServices.setRestTemplate(restTemplate);

		this.remoteTokenServices.loadAuthentication("access-token-1234");
	}

	// gh-838
	@Test(expected = InvalidTokenException.class)
	public void loadAuthenticationWhenIntrospectionResponseMissingActiveAttributeThenThrowInvalidTokenException() throws Exception {
		Map responseAttrs = new HashMap();
		ResponseEntity<Map> response = new ResponseEntity<Map>(responseAttrs, HttpStatus.OK);
		RestTemplate restTemplate = mock(RestTemplate.class);
		when(restTemplate.exchange(anyString(), any(HttpMethod.class), any(HttpEntity.class), any(Class.class))).thenReturn(response);
		this.remoteTokenServices.setRestTemplate(restTemplate);

		this.remoteTokenServices.loadAuthentication("access-token-1234");
	}
}