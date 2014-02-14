/*
 * Copyright 2013 the original author or authors.
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

package org.springframework.security.oauth2.provider.client;

import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;

/**
 * @author Dave Syer
 * 
 */
public class ClientCredentialsTokenEndpointFilterTests {

	private ClientCredentialsTokenEndpointFilter filter = new ClientCredentialsTokenEndpointFilter();
	private AuthenticationManager authenticationManager = Mockito
			.mock(AuthenticationManager.class);

	@Test(expected=IllegalArgumentException.class)
	public void testAuthenticationManagerNeeded() {
		new ClientCredentialsTokenEndpointFilter().afterPropertiesSet();
	}

	@Test(expected = BadCredentialsException.class)
	public void testFailedAuthentication() throws Exception {
		filter.setAuthenticationManager(authenticationManager);
		filter.afterPropertiesSet();
		filter.attemptAuthentication(new MockHttpServletRequest(),
				new MockHttpServletResponse());
	}

	@Test
	public void testAuthentication() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addParameter("client_id", "foo");
		filter.setAuthenticationManager(authenticationManager);
		filter.afterPropertiesSet();
		Authentication authentication = new UsernamePasswordAuthenticationToken(
				"foo", "",
				AuthorityUtils.commaSeparatedStringToAuthorityList("CLIENT"));
		Mockito.when(
				authenticationManager.authenticate(Mockito
						.any(Authentication.class))).thenReturn(authentication);
		assertEquals(authentication, filter.attemptAuthentication(request,
				new MockHttpServletResponse()));
	}

}
