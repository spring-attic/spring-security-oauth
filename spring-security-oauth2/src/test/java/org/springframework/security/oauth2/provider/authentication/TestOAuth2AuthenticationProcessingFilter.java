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


package org.springframework.security.oauth2.provider.authentication;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import javax.servlet.FilterChain;

import org.junit.After;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.RequestTokenFactory;

/**
 * @author Dave Syer
 * 
 */
public class TestOAuth2AuthenticationProcessingFilter {

	private OAuth2AuthenticationProcessingFilter filter = new OAuth2AuthenticationProcessingFilter();

	private MockHttpServletRequest request = new MockHttpServletRequest();

	private Authentication userAuthentication = new UsernamePasswordAuthenticationToken("marissa", "koala");

	private OAuth2Authentication authentication = new OAuth2Authentication(RequestTokenFactory.createOAuth2Request(null, "foo", null, false, null, null, null, null), userAuthentication);

	private FilterChain chain = Mockito.mock(FilterChain.class);

	{
		filter.setAuthenticationManager(new AuthenticationManager() {

			public Authentication authenticate(Authentication request) throws AuthenticationException {
				authentication.setDetails(request.getDetails());
				return authentication;
			}
		});
	}
	
	@After
	public void clear() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void testDetailsAdded() throws Exception {
		request.addHeader("Authorization", "Bearer FOO");
		filter.doFilter(request, null, chain );
		assertNotNull(request.getAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_VALUE));
		Authentication result = SecurityContextHolder.getContext().getAuthentication();
		assertEquals(authentication, result);
		assertNotNull(result.getDetails());
	}

}
