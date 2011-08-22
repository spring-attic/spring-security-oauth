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

import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.createNiceMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.reset;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertSame;

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
public class TestProtectedResourceProcessingFilter {

	/**
	 * test onValidSignature
	 */
	@Test
	public void testOnValidSignature() throws Exception {
		ProtectedResourceProcessingFilter filter = new ProtectedResourceProcessingFilter();
		HttpServletRequest request = createMock(HttpServletRequest.class);
		HttpServletResponse response = createMock(HttpServletResponse.class);
		FilterChain chain = createMock(FilterChain.class);
		ConsumerCredentials creds = new ConsumerCredentials("key", "sig", "meth", "base", "tok");
		ConsumerAuthentication authentication = new ConsumerAuthentication(createNiceMock(ConsumerDetails.class), creds);
		authentication.setAuthenticated(true);
		SecurityContextHolder.getContext().setAuthentication(authentication);
		OAuthProviderTokenServices tokenServices = createMock(OAuthProviderTokenServices.class);
		OAuthAccessProviderToken token = createMock(OAuthAccessProviderToken.class);
		filter.setTokenServices(tokenServices);

		expect(tokenServices.getToken("tok")).andReturn(token);
		expect(token.isAccessToken()).andReturn(true);
		Authentication userAuthentication = createNiceMock(Authentication.class);
		expect(token.getUserAuthentication()).andReturn(userAuthentication);
		chain.doFilter(request, response);
		replay(request, response, chain, tokenServices, token);
		filter.onValidSignature(request, response, chain);
		assertSame(userAuthentication, SecurityContextHolder.getContext().getAuthentication());
		verify(request, response, chain, tokenServices, token);
		reset(request, response, chain, tokenServices, token);

		SecurityContextHolder.getContext().setAuthentication(null);
	}

}
