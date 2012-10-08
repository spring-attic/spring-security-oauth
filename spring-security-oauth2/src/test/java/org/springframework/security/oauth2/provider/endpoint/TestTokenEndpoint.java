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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.AuthorizationRequestManager;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.DefaultAuthorizationRequest;
import org.springframework.security.oauth2.provider.TokenGranter;

/**
 * @author Dave Syer
 * @author Rob Winch
 */
@RunWith(MockitoJUnitRunner.class)
public class TestTokenEndpoint {

	@Mock
	private TokenGranter tokenGranter;

	@Mock
	private AuthorizationRequestManager authorizationRequestFactory;

	@Mock
	private ClientDetailsService clientDetailsService;

	@Test
	public void testGetAccessTokenWithNoClientId() {

		TokenEndpoint endpoint = new TokenEndpoint();
		endpoint.setTokenGranter(tokenGranter);
		endpoint.setAuthorizationRequestManager(authorizationRequestFactory);
		endpoint.setClientDetailsService(clientDetailsService);

		HashMap<String, String> parameters = new HashMap<String, String>();

		OAuth2AccessToken expectedToken = new DefaultOAuth2AccessToken("FOO");
		when(tokenGranter.grant(Mockito.eq("authorization_code"), Mockito.any(AuthorizationRequest.class))).thenReturn(
				expectedToken);
		@SuppressWarnings("unchecked")
		Map<String, String> anyMap = Mockito.any(Map.class);
		when(authorizationRequestFactory.createAuthorizationRequest(anyMap)).thenReturn(
				new DefaultAuthorizationRequest(parameters));

		ResponseEntity<OAuth2AccessToken> response = endpoint.getAccessToken(new UsernamePasswordAuthenticationToken(
				null, null, Collections.singleton(new SimpleGrantedAuthority("ROLE_CLIENT"))), "authorization_code",
				parameters);

		assertNotNull(response);
		assertEquals(HttpStatus.OK, response.getStatusCode());
		OAuth2AccessToken body = response.getBody();
		assertEquals(body, expectedToken);
		assertTrue("Wrong body: " + body, body.getTokenType() != null);
	}

	@Test
	public void testGetAccessTokenWithScope() {

		TokenEndpoint endpoint = new TokenEndpoint();
		endpoint.setTokenGranter(tokenGranter);
		endpoint.setAuthorizationRequestManager(authorizationRequestFactory);
		endpoint.setClientDetailsService(clientDetailsService);

		HashMap<String, String> parameters = new HashMap<String, String>();
		parameters.put("scope", "read");
		parameters.put("grant_type", "authorization_code");
		parameters.put("code", "kJAHDFG");

		OAuth2AccessToken expectedToken = new DefaultOAuth2AccessToken("FOO");
		ArgumentCaptor<AuthorizationRequest> captor = ArgumentCaptor.forClass(AuthorizationRequest.class);
		when(tokenGranter.grant(Mockito.eq("authorization_code"), captor.capture())).thenReturn(expectedToken);
		@SuppressWarnings("unchecked")
		Map<String, String> anyMap = Mockito.any(Map.class);
		when(authorizationRequestFactory.createAuthorizationRequest(anyMap)).thenReturn(
				new DefaultAuthorizationRequest(parameters));

		ResponseEntity<OAuth2AccessToken> response = endpoint.getAccessToken(new UsernamePasswordAuthenticationToken(
				null, null, Collections.singleton(new SimpleGrantedAuthority("ROLE_CLIENT"))), "authorization_code",
				parameters);

		assertNotNull(response);
		assertEquals(HttpStatus.OK, response.getStatusCode());
		OAuth2AccessToken body = response.getBody();
		assertEquals(body, expectedToken);
		assertTrue("Wrong body: " + body, body.getTokenType() != null);
		assertTrue("Scope of token request not cleared", captor.getValue().getScope().isEmpty());
	}

}
