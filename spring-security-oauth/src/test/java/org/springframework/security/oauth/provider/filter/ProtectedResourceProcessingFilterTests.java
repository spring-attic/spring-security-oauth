/*
 * Copyright 2008 Web Cohesion
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.oauth.provider.filter;

import static org.junit.Assert.assertSame;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth.provider.ConsumerAuthentication;
import org.springframework.security.oauth.provider.ConsumerCredentials;
import org.springframework.security.oauth.provider.ConsumerDetails;
import org.springframework.security.oauth.provider.filter.ProtectedResourceProcessingFilter;
import org.springframework.security.oauth.provider.token.OAuthAccessProviderToken;
import org.springframework.security.oauth.provider.token.OAuthProviderTokenServices;

/**
 * @author Ryan Heaton
 */
public class ProtectedResourceProcessingFilterTests {

	/**
	 * test onValidSignature
	 */
	@Test
	public void testOnValidSignature() throws Exception {
		ProtectedResourceProcessingFilter filter = new ProtectedResourceProcessingFilter();
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		FilterChain chain = mock(FilterChain.class);
		ConsumerCredentials creds = new ConsumerCredentials("key", "sig", "meth", "base", "tok");
		ConsumerAuthentication authentication = new ConsumerAuthentication(mock(ConsumerDetails.class), creds);
		authentication.setAuthenticated(true);
		SecurityContextHolder.getContext().setAuthentication(authentication);
		OAuthProviderTokenServices tokenServices = mock(OAuthProviderTokenServices.class);
		OAuthAccessProviderToken token = mock(OAuthAccessProviderToken.class);
		filter.setTokenServices(tokenServices);

		when(tokenServices.getToken("tok")).thenReturn(token);
		when(token.isAccessToken()).thenReturn(true);
		Authentication userAuthentication = mock(Authentication.class);
		when(token.getUserAuthentication()).thenReturn(userAuthentication);

		filter.onValidSignature(request, response, chain);

		verify(chain).doFilter(request, response);
		assertSame(userAuthentication, SecurityContextHolder.getContext().getAuthentication());
		SecurityContextHolder.getContext().setAuthentication(null);
	}

}
