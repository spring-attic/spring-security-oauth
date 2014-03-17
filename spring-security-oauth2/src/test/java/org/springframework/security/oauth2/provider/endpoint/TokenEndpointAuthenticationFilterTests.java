/*
 * Copyright 2012-2013 the original author or authors.
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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;

/**
 * @author Dave Syer
 * 
 */
public class TokenEndpointAuthenticationFilterTests {

	private MockHttpServletRequest request = new MockHttpServletRequest();

	private MockHttpServletResponse response = new MockHttpServletResponse();

	private MockFilterChain chain = new MockFilterChain();

	private AuthenticationManager authenticationManager = Mockito.mock(AuthenticationManager.class);
	
	private BaseClientDetails client = new BaseClientDetails("foo", "resource", "scope", "authorization_code",
			"ROLE_CLIENT");

	private ClientDetailsService clientDetailsService = new ClientDetailsService() {
		public ClientDetails loadClientByClientId(String clientId) throws OAuth2Exception {
			return client;
		}
	};
	
	private OAuth2RequestFactory oAuth2RequestFactory = new DefaultOAuth2RequestFactory(clientDetailsService);

	@Before
	public void init() {
		SecurityContextHolder.clearContext();
		SecurityContextHolder.getContext().setAuthentication(
				new UsernamePasswordAuthenticationToken("client", "secret", AuthorityUtils
						.commaSeparatedStringToAuthorityList("ROLE_CLIENT")));
	}

	@After
	public void close() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void testPasswordGrant() throws Exception {
		request.setParameter("grant_type", "password");
		request.setParameter("client_id", "foo");
		Mockito.when(authenticationManager.authenticate(Mockito.<Authentication> any())).thenReturn(
				new UsernamePasswordAuthenticationToken("foo", "bar", AuthorityUtils
						.commaSeparatedStringToAuthorityList("ROLE_USER")));
		TokenEndpointAuthenticationFilter filter = new TokenEndpointAuthenticationFilter(authenticationManager, oAuth2RequestFactory);
		filter.doFilter(request, response, chain);
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		assertTrue(authentication instanceof OAuth2Authentication);
		assertTrue(authentication.isAuthenticated());
	}

	@Test
	public void testPasswordGrantWithUnAuthenticatedClient() throws Exception {
		SecurityContextHolder.getContext().setAuthentication(
				new UsernamePasswordAuthenticationToken("client", "secret"));
		request.setParameter("grant_type", "password");
		Mockito.when(authenticationManager.authenticate(Mockito.<Authentication> any())).thenReturn(
				new UsernamePasswordAuthenticationToken("foo", "bar", AuthorityUtils
						.commaSeparatedStringToAuthorityList("ROLE_USER")));
		TokenEndpointAuthenticationFilter filter = new TokenEndpointAuthenticationFilter(authenticationManager, oAuth2RequestFactory);
		filter.doFilter(request, response, chain);
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		assertTrue(authentication instanceof OAuth2Authentication);
		assertFalse(authentication.isAuthenticated());
	}

	@Test
	public void testNoGrantType() throws Exception {
		TokenEndpointAuthenticationFilter filter = new TokenEndpointAuthenticationFilter(authenticationManager, oAuth2RequestFactory);
		filter.doFilter(request, response, chain);
		// Just the client
		assertTrue(SecurityContextHolder.getContext().getAuthentication() instanceof UsernamePasswordAuthenticationToken);
	}

}
