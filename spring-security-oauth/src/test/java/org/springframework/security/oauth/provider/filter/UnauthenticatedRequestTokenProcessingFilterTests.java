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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.TreeMap;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth.common.OAuthConsumerParameter;
import org.springframework.security.oauth.provider.ConsumerAuthentication;
import org.springframework.security.oauth.provider.ConsumerCredentials;
import org.springframework.security.oauth.provider.ConsumerDetails;
import org.springframework.security.oauth.provider.filter.UnauthenticatedRequestTokenProcessingFilter;
import org.springframework.security.oauth.provider.token.OAuthAccessProviderToken;
import org.springframework.security.oauth.provider.token.OAuthProviderToken;
import org.springframework.security.oauth.provider.token.OAuthProviderTokenServices;

/**
 * @author Ryan Heaton
 */
public class UnauthenticatedRequestTokenProcessingFilterTests {

	/**
	 * test onValidSignature
	 */
	@Test
	public void testOnValidSignature() throws Exception {
		final OAuthProviderToken authToken = mock(OAuthProviderToken.class);
		UnauthenticatedRequestTokenProcessingFilter filter = new UnauthenticatedRequestTokenProcessingFilter() {
			@Override
			protected OAuthProviderToken createOAuthToken(ConsumerAuthentication authentication) {
				return authToken;
			}
		};
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		FilterChain filterChain = mock(FilterChain.class);
		ConsumerCredentials creds = new ConsumerCredentials("key", "sig", "meth", "base", "tok");
		ConsumerDetails consumerDetails = mock(ConsumerDetails.class);

		when(authToken.getConsumerKey()).thenReturn("chi");
		when(authToken.getValue()).thenReturn("tokvalue");
		when(authToken.getSecret()).thenReturn("shhhhhh");
		when(consumerDetails.getAuthorities()).thenReturn(new ArrayList<GrantedAuthority>());
		when(consumerDetails.getConsumerKey()).thenReturn("chi");
		response.setContentType("text/plain;charset=utf-8");
		StringWriter writer = new StringWriter();
		when(response.getWriter()).thenReturn(new PrintWriter(writer));
		response.flushBuffer();
		TreeMap<String, String> params = new TreeMap<String, String>();
		params.put(OAuthConsumerParameter.oauth_callback.toString(), "mycallback");
		ConsumerAuthentication authentication = new ConsumerAuthentication(consumerDetails, creds, params);
		authentication.setAuthenticated(true);
		SecurityContextHolder.getContext().setAuthentication(authentication);

		filter.onValidSignature(request, response, filterChain);

		assertEquals("oauth_token=tokvalue&oauth_token_secret=shhhhhh&oauth_callback_confirmed=true", writer.toString());

		SecurityContextHolder.getContext().setAuthentication(null);
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

		UnauthenticatedRequestTokenProcessingFilter filter = new UnauthenticatedRequestTokenProcessingFilter();
		filter.setTokenServices(tokenServices);

		when(consumerDetails.getConsumerKey()).thenReturn("chi");
		when(consumerDetails.getAuthorities()).thenReturn(new ArrayList<GrantedAuthority>());
		when(tokenServices.createUnauthorizedRequestToken("chi", "callback")).thenReturn(token);
		TreeMap<String, String> map = new TreeMap<String, String>();
		map.put(OAuthConsumerParameter.oauth_callback.toString(), "callback");
		ConsumerAuthentication authentication = new ConsumerAuthentication(consumerDetails, creds, map);

		assertSame(token, filter.createOAuthToken(authentication));
	}

}
