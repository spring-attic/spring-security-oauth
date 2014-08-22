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
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth.common.OAuthParameters;
import org.springframework.security.oauth.provider.ConsumerAuthentication;
import org.springframework.security.oauth.provider.ConsumerCredentials;
import org.springframework.security.oauth.provider.ConsumerDetails;
import org.springframework.security.oauth.provider.InvalidOAuthParametersException;
import org.springframework.security.oauth.provider.token.OAuthAccessProviderToken;
import org.springframework.security.oauth.provider.token.OAuthProviderToken;
import org.springframework.security.oauth.provider.token.OAuthProviderTokenServices;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * @author Ryan Heaton
 * @author <a rel="author" href="http://autayeu.com/">Aliaksandr Autayeu</a>
 */
public class RequestTokenEndpointTests {

	@Test
	public void testGetRequestToken() throws Exception {
		final OAuthProviderToken authToken = mock(OAuthProviderToken.class);
		RequestTokenEndpoint endpoint = new RequestTokenEndpoint() {
			@Override
			protected OAuthProviderToken createOAuthToken(ConsumerAuthentication authentication) {
				return authToken;
			}
		};
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);


		SecurityContextHolder.clearContext();
		// negative case  - no auth
		try {
			endpoint.getRequestToken(request, response);
			fail("should have thrown InvalidOAuthParametersException");
		} catch (InvalidOAuthParametersException e) {
			// no-op
		}

		ConsumerCredentials creds = new ConsumerCredentials("key", "sig", "meth", "base", "tok");
		ConsumerDetails consumerDetails = mock(ConsumerDetails.class);
		OAuthParameters params = mock(OAuthParameters.class);
		ConsumerAuthentication authentication = new ConsumerAuthentication(consumerDetails, creds, params);
		authentication.setAuthenticated(true);
		SecurityContextHolder.getContext().setAuthentication(authentication);

		// negative case  - no callback
		try {
			endpoint.getRequestToken(request, response);
			fail("should have thrown InvalidOAuthParametersException");
		} catch (InvalidOAuthParametersException e) {
			// no-op
		}

		when(params.getCallback()).thenReturn("mycallback");

		when(authToken.getConsumerKey()).thenReturn("chi");
		when(consumerDetails.getConsumerKey()).thenReturn("differ");

		// negative case  - consumer keys differ
		try {
			endpoint.getRequestToken(request, response);
			fail("should have thrown IllegalStateException");
		} catch (IllegalStateException e) {
			// no-op
		}

		when(consumerDetails.getConsumerKey()).thenReturn("chi");

		when(authToken.getValue()).thenReturn("tokvalue");
		when(authToken.getSecret()).thenReturn("shhhhhh");
		StringWriter writer = new StringWriter();
		when(response.getWriter()).thenReturn(new PrintWriter(writer));
		response.flushBuffer();

		endpoint.getRequestToken(request, response);

		assertEquals("oauth_token=tokvalue&oauth_token_secret=shhhhhh&oauth_callback_confirmed=true", writer.toString());

		SecurityContextHolder.clearContext();
	}

	/**
	 * tests creating the oauth token.
	 */
	@Test
	public void testCreateOAuthToken() throws Exception {
		ConsumerDetails consumerDetails = mock(ConsumerDetails.class);
		ConsumerCredentials creds = new ConsumerCredentials("key", "sig", "meth", "base", "tok");
		OAuthProviderTokenServices tokenServices = mock(OAuthProviderTokenServices.class);
		OAuthAccessProviderToken token = mock(OAuthAccessProviderToken.class);

		RequestTokenEndpoint filter = new RequestTokenEndpoint();
		filter.setTokenServices(tokenServices);

		when(consumerDetails.getConsumerKey()).thenReturn("chi");
		when(consumerDetails.getAuthorities()).thenReturn(new ArrayList<GrantedAuthority>());
		when(tokenServices.createUnauthorizedRequestToken("chi", "callback")).thenReturn(token);
		OAuthParameters map = new OAuthParameters();
		map.setCallback("callback");
		ConsumerAuthentication authentication = new ConsumerAuthentication(consumerDetails, creds, map);

		assertSame(token, filter.createOAuthToken(authentication));
	}

}
