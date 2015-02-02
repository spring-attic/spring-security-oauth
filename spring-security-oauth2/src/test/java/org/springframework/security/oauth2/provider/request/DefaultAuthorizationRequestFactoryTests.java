/*
 * Copyright 2006-2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package org.springframework.security.oauth2.provider.request;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

/**
 * @author Dave Syer
 * 
 */
public class DefaultAuthorizationRequestFactoryTests {

	private BaseClientDetails client = new BaseClientDetails();

	private DefaultOAuth2RequestFactory factory = new DefaultOAuth2RequestFactory(new ClientDetailsService() {
		public ClientDetails loadClientByClientId(String clientId) throws OAuth2Exception {
			return client;
		}
	});

	@Before
	public void start() {
		client.setClientId("foo");
		client.setScope(Collections.singleton("bar"));
		client.setResourceIds(Arrays.asList("bar"));
	}

	@After
	public void close() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void testCreateAuthorizationRequest() {
		AuthorizationRequest request = factory.createAuthorizationRequest(Collections.singletonMap("client_id", "foo"));
		assertEquals("foo", request.getClientId());
	}

	@Test
	public void testCreateTokenRequest() {
		TokenRequest request = factory.createTokenRequest(Collections.singletonMap("client_id", "foo"), client);
		assertEquals("foo", request.getClientId());
	}

	@Test
	public void testCreateAuthorizationRequestWithDefaultScopes() {
		AuthorizationRequest request = factory.createAuthorizationRequest(Collections.singletonMap("client_id", "foo"));
		assertEquals("[bar]", request.getScope().toString());
	}

	@Test
	public void testCreateAuthorizationRequestWithUserRoles() {
		factory.setCheckUserScopes(true);
		AuthorizationRequest request = factory.createAuthorizationRequest(Collections.singletonMap("client_id", "foo"));
		assertEquals("foo", request.getClientId());
		assertEquals("[bar]", request.getScope().toString());
	}

	@Test
	public void testCreateAuthorizationThenOAuth2RequestWithGrantType() {
		factory.setCheckUserScopes(true);
		Map<String,String> parameters = new HashMap<String, String>();
		parameters.put("client_id", "foo");
		parameters.put("response_type", "token");
		OAuth2Request request = factory.createAuthorizationRequest(parameters).createOAuth2Request();
		assertEquals("implicit", request.getGrantType());
	}

	@Test
	public void testCreateTokenThenOAuth2RequestWithGrantType() {
		factory.setCheckUserScopes(true);
		AuthorizationRequest auth = factory.createAuthorizationRequest(Collections.singletonMap("client_id", "foo"));
		OAuth2Request request = factory.createTokenRequest(auth, "password").createOAuth2Request(client);
		assertEquals("password", request.getGrantType());
		assertEquals("[bar]", request.getResourceIds().toString());
	}

	@Test
	public void testPasswordErased() {
		factory.setCheckUserScopes(true);
		Map<String, String> params = new HashMap<String, String>(Collections.singletonMap("client_id", "foo"));
		params.put("password", "shhh");		
		AuthorizationRequest auth = factory.createAuthorizationRequest(params);
		OAuth2Request request = factory.createTokenRequest(auth, "password").createOAuth2Request(client);
		assertNull(request.getRequestParameters().get("password"));
	}

	@Test
	public void testSecretErased() {
		factory.setCheckUserScopes(true);
		Map<String, String> params = new HashMap<String, String>(Collections.singletonMap("client_id", "foo"));
		params.put("client_secret", "shhh");		
		AuthorizationRequest auth = factory.createAuthorizationRequest(params);
		OAuth2Request request = factory.createTokenRequest(auth, "client_credentials").createOAuth2Request(client);
		assertNull(request.getRequestParameters().get("client_secret"));
	}

	@Test
	public void testCreateAuthorizationRequestWhenUserNotPermitted() {
		SecurityContextHolder.getContext().setAuthentication(
				new UsernamePasswordAuthenticationToken("user", "N/A", AuthorityUtils
						.commaSeparatedStringToAuthorityList("ROLE_BAR")));
		factory.setCheckUserScopes(true);
		client.setScope(Collections.singleton("foo"));
		AuthorizationRequest request = factory.createAuthorizationRequest(Collections.singletonMap("client_id", "foo"));
		assertEquals("foo", request.getClientId());
		assertEquals("[]", request.getScope().toString());
	}

}
