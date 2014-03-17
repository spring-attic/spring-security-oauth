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

import java.util.Collections;

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
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;

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
