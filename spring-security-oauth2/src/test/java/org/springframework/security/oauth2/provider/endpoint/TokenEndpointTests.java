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

import java.security.Principal;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.web.HttpRequestMethodNotSupportedException;

/**
 * @author Dave Syer
 * @author Rob Winch
 */
@RunWith(MockitoJUnitRunner.class)
public class TokenEndpointTests {

	@Mock
	private TokenGranter tokenGranter;

	@Mock
	private OAuth2RequestFactory authorizationRequestFactory;

	@Mock
	private ClientDetailsService clientDetailsService;

	private String clientId = "client";
	private BaseClientDetails clientDetails = new BaseClientDetails();

	private TokenEndpoint endpoint;

	private Principal clientAuthentication = new UsernamePasswordAuthenticationToken("client", null,
			Collections.singleton(new SimpleGrantedAuthority("ROLE_CLIENT")));

	private TokenRequest createFromParameters(Map<String, String> parameters) {
		TokenRequest request = new TokenRequest(parameters, parameters.get(OAuth2Utils.CLIENT_ID),
				OAuth2Utils.parseParameterList(parameters.get(OAuth2Utils.SCOPE)),
				parameters.get(OAuth2Utils.GRANT_TYPE));
		return request;
	}

	@Before
	public void init() {
		endpoint = new TokenEndpoint();
		endpoint.setTokenGranter(tokenGranter);
		endpoint.setOAuth2RequestFactory(authorizationRequestFactory);
		endpoint.setClientDetailsService(clientDetailsService);
		clientDetails.setClientId(clientId);
	}

	@Test
	public void testGetAccessTokenWithNoClientId() throws HttpRequestMethodNotSupportedException {

		HashMap<String, String> parameters = new HashMap<String, String>();
		parameters.put(OAuth2Utils.GRANT_TYPE, "authorization_code");

		OAuth2AccessToken expectedToken = new DefaultOAuth2AccessToken("FOO");
		when(tokenGranter.grant(Mockito.eq("authorization_code"), Mockito.any(TokenRequest.class))).thenReturn(
				expectedToken);
		@SuppressWarnings("unchecked")
		Map<String, String> anyMap = Mockito.any(Map.class);
		when(authorizationRequestFactory.createTokenRequest(anyMap, Mockito.any(ClientDetails.class))).thenReturn(
				createFromParameters(parameters));

		clientAuthentication = new UsernamePasswordAuthenticationToken(null, null,
				Collections.singleton(new SimpleGrantedAuthority("ROLE_CLIENT")));
		ResponseEntity<OAuth2AccessToken> response = endpoint.postAccessToken(clientAuthentication, parameters);

		assertNotNull(response);
		assertEquals(HttpStatus.OK, response.getStatusCode());
		OAuth2AccessToken body = response.getBody();
		assertEquals(body, expectedToken);
		assertTrue("Wrong body: " + body, body.getTokenType() != null);
	}

	@Test
	public void testGetAccessTokenWithScope() throws HttpRequestMethodNotSupportedException {

		when(clientDetailsService.loadClientByClientId(clientId)).thenReturn(clientDetails);

		HashMap<String, String> parameters = new HashMap<String, String>();
		parameters.put("client_id", clientId);
		parameters.put("scope", "read");
		parameters.put("grant_type", "authorization_code");
		parameters.put("code", "kJAHDFG");

		OAuth2AccessToken expectedToken = new DefaultOAuth2AccessToken("FOO");
		ArgumentCaptor<TokenRequest> captor = ArgumentCaptor.forClass(TokenRequest.class);

		when(tokenGranter.grant(Mockito.eq("authorization_code"), captor.capture())).thenReturn(expectedToken);
		@SuppressWarnings("unchecked")
		Map<String, String> anyMap = Mockito.any(Map.class);
		when(authorizationRequestFactory.createTokenRequest(anyMap, Mockito.eq(clientDetails))).thenReturn(
				createFromParameters(parameters));

		ResponseEntity<OAuth2AccessToken> response = endpoint.postAccessToken(clientAuthentication, parameters);

		assertNotNull(response);
		assertEquals(HttpStatus.OK, response.getStatusCode());
		OAuth2AccessToken body = response.getBody();
		assertEquals(body, expectedToken);
		assertTrue("Wrong body: " + body, body.getTokenType() != null);
		assertTrue("Scope of token request not cleared", captor.getValue().getScope().isEmpty());
	}

    @Test(expected = HttpRequestMethodNotSupportedException.class)
    public void testGetAccessTokenWithUnsupportedRequestParameters() throws HttpRequestMethodNotSupportedException {
        endpoint.getAccessToken(clientAuthentication, new HashMap<String, String>());
    }

	@Test
	public void testGetAccessTokenWithSupportedRequestParametersNotPost() throws HttpRequestMethodNotSupportedException {
		endpoint.setAllowedRequestMethods(new HashSet<HttpMethod>(Arrays.asList(HttpMethod.GET)));
		HashMap<String, String> parameters = new HashMap<String, String>();
		parameters.put("client_id", clientId);
		parameters.put("scope", "read");
		parameters.put("grant_type", "authorization_code");
		parameters.put("code", "kJAHDFG");

		OAuth2AccessToken expectedToken = new DefaultOAuth2AccessToken("FOO");
		when(tokenGranter.grant(Mockito.eq("authorization_code"), Mockito.any(TokenRequest.class))).thenReturn(
				expectedToken);
		@SuppressWarnings("unchecked")
		Map<String, String> anyMap = Mockito.any(Map.class);
		when(authorizationRequestFactory.createTokenRequest(anyMap, Mockito.any(ClientDetails.class))).thenReturn(
				createFromParameters(parameters));

		ResponseEntity<OAuth2AccessToken> response = endpoint.getAccessToken(clientAuthentication, parameters);
		assertNotNull(response);
		assertEquals(HttpStatus.OK, response.getStatusCode());
		OAuth2AccessToken body = response.getBody();
		assertEquals(body, expectedToken);
		assertTrue("Wrong body: " + body, body.getTokenType() != null);
	}

	@Test(expected = InvalidGrantException.class)
	public void testImplicitGrant() throws HttpRequestMethodNotSupportedException {
		HashMap<String, String> parameters = new HashMap<String, String>();
		parameters.put(OAuth2Utils.GRANT_TYPE, "implicit");
		parameters.put("client_id", clientId);
		parameters.put("scope", "read");
		@SuppressWarnings("unchecked")
		Map<String, String> anyMap = Mockito.any(Map.class);
		when(authorizationRequestFactory.createTokenRequest(anyMap, Mockito.eq(clientDetails))).thenReturn(
				createFromParameters(parameters));
		when(clientDetailsService.loadClientByClientId(clientId)).thenReturn(clientDetails);
		endpoint.postAccessToken(clientAuthentication, parameters);
	}
}
