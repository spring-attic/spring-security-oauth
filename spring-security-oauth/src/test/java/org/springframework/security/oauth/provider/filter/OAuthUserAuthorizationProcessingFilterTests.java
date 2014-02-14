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

import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Test;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth.provider.token.OAuthProviderTokenImpl;
import org.springframework.security.oauth.provider.token.OAuthProviderTokenServices;
import org.springframework.security.oauth.provider.verifier.OAuthVerifierServices;

/**
 * @author Ryan Heaton
 */
public class OAuthUserAuthorizationProcessingFilterTests {

	/**
	 * tests the attempt to authenticate.
	 */
	@Test
	public void testAttemptAuthentication() throws Exception {
		UserAuthorizationProcessingFilter filter = new UserAuthorizationProcessingFilter("/");
		OAuthVerifierServices vs = mock(OAuthVerifierServices.class);
		filter.setVerifierServices(vs);
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		Authentication authentication = mock(Authentication.class);
		OAuthProviderTokenServices tokenServices = mock(OAuthProviderTokenServices.class);
		filter.setTokenServices(tokenServices);

		SecurityContextHolder.getContext().setAuthentication(authentication);
		when(request.getParameter("requestToken")).thenReturn("tok");
		OAuthProviderTokenImpl token = new OAuthProviderTokenImpl();
		token.setCallbackUrl("callback");
		when(tokenServices.getToken("tok")).thenReturn(token);
		when(authentication.isAuthenticated()).thenReturn(false);
		try {
			filter.attemptAuthentication(request, response);
			fail();
		} catch (InsufficientAuthenticationException e) {
		}
		verify(request).setAttribute(UserAuthorizationProcessingFilter.CALLBACK_ATTRIBUTE, "callback");
		reset(request);

		when(authentication.isAuthenticated()).thenReturn(true);
		when(request.getParameter("requestToken")).thenReturn("tok");
		when(tokenServices.getToken("tok")).thenReturn(token);
		when(vs.createVerifier()).thenReturn("verifier");
		tokenServices.authorizeRequestToken("tok", "verifier", authentication);
		filter.setTokenServices(tokenServices);

		filter.attemptAuthentication(request, response);

		verify(request).setAttribute(UserAuthorizationProcessingFilter.CALLBACK_ATTRIBUTE, "callback");
		verify(request).setAttribute(UserAuthorizationProcessingFilter.VERIFIER_ATTRIBUTE, "verifier");
		SecurityContextHolder.getContext().setAuthentication(null);
	}

}
