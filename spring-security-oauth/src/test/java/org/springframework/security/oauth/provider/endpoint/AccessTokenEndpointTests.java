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
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth.common.OAuthParameters;
import org.springframework.security.oauth.provider.*;
import org.springframework.security.oauth.provider.token.OAuthAccessProviderToken;
import org.springframework.security.oauth.provider.token.OAuthProviderToken;
import org.springframework.security.oauth.provider.token.OAuthProviderTokenServices;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

/**
 * @author Ryan Heaton
 * @author <a rel="author" href="http://autayeu.com/">Aliaksandr Autayeu</a>
 */
@RunWith (MockitoJUnitRunner.class)
public class AccessTokenEndpointTests {
	@Mock
	private ConsumerDetails consumerDetails;
	@Mock
	private OAuthProviderTokenServices tokenServices;
	@Mock
	private OAuthAccessProviderToken token;
	@Mock
	private HttpServletRequest request;
	@Mock
	private HttpServletResponse response;


	/**
	 * tests creating the oauth token.
	 */
	@Test
	public void testCreateOAuthToken() throws Exception {
		ConsumerCredentials creds = new ConsumerCredentials("key", "sig", "meth", "base", "tok");
		when(consumerDetails.getAuthorities()).thenReturn(new ArrayList<GrantedAuthority>());

		AccessTokenEndpoint filter = new AccessTokenEndpoint();
		filter.setTokenServices(tokenServices);

		when(tokenServices.createAccessToken("tok")).thenReturn(token);
		ConsumerAuthentication authentication = new ConsumerAuthentication(consumerDetails, creds);
		assertSame(token, filter.createOAuthAccessToken(authentication));
	}

	@Test
	public void testGetAccessToken() throws IOException {
		AccessTokenEndpoint endpoint = new AccessTokenEndpoint();
		endpoint.setTokenServices(tokenServices);

		SecurityContextHolder.clearContext();
		// negative case  - no auth
		try {
			endpoint.getAccessToken(request, response);
			fail("should have thrown InvalidOAuthParametersException");
		} catch (InvalidOAuthParametersException e) {
			// no-op
		}

		ConsumerAuthentication authentication = mock(ConsumerAuthentication.class);
		SecurityContextHolder.getContext().setAuthentication(authentication);
		OAuthParameters oAuthParameters = mock(OAuthParameters.class);
		when(authentication.getOAuthParameters()).thenReturn(oAuthParameters);
		when(oAuthParameters.getToken()).thenReturn(null);

		// negative case - no authToken
		try {
			endpoint.getAccessToken(request, response);
			fail("should have thrown InvalidOAuthParametersException");
		} catch (InvalidOAuthParametersException e) {
			// no-op
		}

		when(oAuthParameters.getToken()).thenReturn("tok");
		when(oAuthParameters.getVerifier()).thenReturn(null);

		// negative case - no verifier
		try {
			endpoint.getAccessToken(request, response);
			fail("should have thrown InvalidOAuthParametersException");
		} catch (InvalidOAuthParametersException e) {
			// no-op
		}

		when(oAuthParameters.getVerifier()).thenReturn("ver");
		OAuthProviderToken requestToken = mock(OAuthProviderToken.class);
		when(tokenServices.getToken("tok")).thenReturn(requestToken);
		when(requestToken.getVerifier()).thenReturn("differ");

		// negative case - verifiers differ
		try {
			endpoint.getAccessToken(request, response);
			fail("should have thrown InvalidOAuthParametersException");
		} catch (InvalidOAuthParametersException e) {
			// no-op
		}

		when(requestToken.getVerifier()).thenReturn("ver");

		when(authentication.getConsumerCredentials()).thenReturn(new ConsumerCredentials("conKey", "sig", "method", "base", "authToken"));
		when(authentication.getConsumerDetails()).thenReturn(consumerDetails);
		when(consumerDetails.getConsumerKey()).thenReturn("conKey");
		OAuthAccessProviderToken authToken = mock(OAuthAccessProviderToken.class);
		when(tokenServices.createAccessToken(anyString())).thenReturn(authToken);
		when(authToken.getSecret()).thenReturn("shhhhhh");
		when(authToken.getValue()).thenReturn("tokvalue");

		when(authToken.getConsumerKey()).thenReturn("diffKey");
		// negative case - consumer keys differ
		try {
			endpoint.getAccessToken(request, response);
			fail("should have thrown IllegalStateException");
		} catch (IllegalStateException e) {
			// no-op
		}

		when(authToken.getConsumerKey()).thenReturn("conKey");

		StringWriter writer = new StringWriter();
		when(response.getWriter()).thenReturn(new PrintWriter(writer));
		response.flushBuffer();

		endpoint.getAccessToken(request, response);
		assertEquals("oauth_token=tokvalue&oauth_token_secret=shhhhhh", writer.toString());

		SecurityContextHolder.clearContext();
	}
}
