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
package org.springframework.security.oauth.provider.endpoint;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth.provider.InvalidOAuthParametersException;
import org.springframework.security.oauth.provider.token.InvalidOAuthTokenException;
import org.springframework.security.oauth.provider.token.OAuthProviderToken;
import org.springframework.security.oauth.provider.token.OAuthProviderTokenServices;
import org.springframework.security.oauth.provider.verifier.OAuthVerifierServices;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * @author Ryan Heaton
 * @author <a rel="author" href="http://autayeu.com/">Aliaksandr Autayeu</a>
 */
@RunWith ( MockitoJUnitRunner.class )
public class AuthorizationEndpointTests {

	@Mock
	private HttpServletRequest request;

	@Mock
	private HttpServletResponse response;

	/**
	 * tests the attempt to authenticate.
	 */
	@Test
	public void testAuthentication() throws Exception {
		AuthorizationEndpoint endpoint = new AuthorizationEndpoint();
		OAuthVerifierServices vs = mock(OAuthVerifierServices.class);
		endpoint.setVerifierServices(vs);
		OAuthProviderTokenServices tokenServices = mock(OAuthProviderTokenServices.class);
		endpoint.setTokenServices(tokenServices);

		// negative case - no token
		try {
			endpoint.authorize(request, response);
			fail("should have thrown InvalidOAuthParametersException");
		} catch (InvalidOAuthParametersException e) {
			// no-op
		}

		when(request.getParameter("requestToken")).thenReturn("tok");

		SecurityContextHolder.clearContext();
		// negative case - not auth
		try {
			endpoint.authorize(request, response);
			fail("should have thrown InsufficientAuthenticationException");
		} catch (InsufficientAuthenticationException e) {
			// no-op
		}

		Authentication authentication = mock(Authentication.class);
		SecurityContextHolder.getContext().setAuthentication(authentication);

		// negative case - not auth
		when(authentication.isAuthenticated()).thenReturn(false);
		try {
			endpoint.authorize(request, response);
			fail("should have thrown InsufficientAuthenticationException");
		} catch (InsufficientAuthenticationException e) {
			// no-op
		}

		when(authentication.isAuthenticated()).thenReturn(true);

		// negative case - no token
		try {
			endpoint.authorize(request, response);
			fail("should have thrown InvalidOAuthTokenException");
		} catch (InvalidOAuthTokenException e) {
			// no-op
		}

		OAuthProviderToken token = mock(OAuthProviderToken.class);
		when(tokenServices.getToken("tok")).thenReturn(token);

		// negative case - no callback
		try {
			endpoint.authorize(request, response);
			fail("should have thrown InvalidOAuthTokenException");
		} catch (InvalidOAuthTokenException e) {
			// no-op
		}

		when(token.getCallbackUrl()).thenReturn("callback");
		when(vs.createVerifier()).thenReturn("verifier");

		endpoint.authorize(request, response);

		verify(tokenServices).authorizeRequestToken("tok", "verifier", authentication);
		verify(request).setAttribute(AuthorizationEndpoint.CALLBACK_ATTRIBUTE, "callback");
		verify(request).setAttribute(AuthorizationEndpoint.VERIFIER_ATTRIBUTE, "verifier");

		SecurityContextHolder.clearContext();
	}

	@Test
	public void testFailedAuthentication() throws Exception {
		AuthorizationEndpoint endpoint = new AuthorizationEndpoint();
		AuthenticationException exception = mock(AuthenticationException.class);
		AuthenticationFailureHandler failureHandler = mock(AuthenticationFailureHandler.class);
		endpoint.setAuthenticationFailureHandler(failureHandler);

		endpoint.unsuccessfulAuthentication(request, response, exception);
		verify(failureHandler).onAuthenticationFailure(request, response, exception);
		assertNull(SecurityContextHolder.getContext().getAuthentication());
	}
}
