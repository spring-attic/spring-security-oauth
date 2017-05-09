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

import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.resource.OAuth2AccessDeniedException;
import org.springframework.security.oauth2.provider.*;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

import java.util.Collections;
import java.util.Set;

/**
 * @author Dave Syer
 * 
 */
public class OAuth2AuthenticationManagerTests {

	private OAuth2AuthenticationManager manager = new OAuth2AuthenticationManager();

	private ResourceServerTokenServices tokenServices = Mockito.mock(ResourceServerTokenServices.class);

	private Authentication userAuthentication = new UsernamePasswordAuthenticationToken("marissa", "koala");

	private OAuth2Authentication authentication = new OAuth2Authentication(
			RequestTokenFactory.createOAuth2Request("foo", false), userAuthentication);

	{
		manager.setTokenServices(tokenServices);
	}

	@Test
	public void testDetailsAdded() throws Exception {
		Mockito.when(tokenServices.loadAuthentication("FOO")).thenReturn(authentication);
		PreAuthenticatedAuthenticationToken request = new PreAuthenticatedAuthenticationToken("FOO", "");
		request.setDetails("BAR");
		Authentication result = manager.authenticate(request);
		assertEquals(authentication, result);
		assertEquals("BAR", result.getDetails());
	}

	@Test
	public void testDetailsEnhanced() throws Exception {
		authentication.setDetails("DETAILS");
		Mockito.when(tokenServices.loadAuthentication("FOO")).thenReturn(authentication);
		PreAuthenticatedAuthenticationToken request = new PreAuthenticatedAuthenticationToken("FOO", "");
		MockHttpServletRequest servletRequest = new MockHttpServletRequest();
		servletRequest.setAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_VALUE, "BAR");
		OAuth2AuthenticationDetails details = new OAuth2AuthenticationDetails(servletRequest);
		request.setDetails(details);
		Authentication result = manager.authenticate(request);
		assertEquals(authentication, result);
		assertEquals("BAR", ((OAuth2AuthenticationDetails) result.getDetails()).getTokenValue());
		assertEquals("DETAILS", ((OAuth2AuthenticationDetails) result.getDetails()).getDecodedDetails());
	}

	@Test
	public void testDetailsEnhancedOnce() throws Exception {
		authentication.setDetails("DETAILS");
		Mockito.when(tokenServices.loadAuthentication("FOO")).thenReturn(authentication);
		PreAuthenticatedAuthenticationToken request = new PreAuthenticatedAuthenticationToken("FOO", "");
		MockHttpServletRequest servletRequest = new MockHttpServletRequest();
		servletRequest.setAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_VALUE, "BAR");
		OAuth2AuthenticationDetails details = new OAuth2AuthenticationDetails(servletRequest);
		request.setDetails(details);
		Authentication result = manager.authenticate(request);
		// Authenticate the same request again to simulate what happens if the app is caching the result from
		// tokenServices.loadAuthentication():
		result = manager.authenticate(request);
		assertEquals(authentication, result);
		assertEquals("BAR", ((OAuth2AuthenticationDetails) result.getDetails()).getTokenValue());
		assertEquals("DETAILS", ((OAuth2AuthenticationDetails) result.getDetails()).getDecodedDetails());
	}

	@Test
	public void testCheckRequestDetails() {
		OAuth2AuthenticationManager manager = new OAuth2AuthenticationManager();
		Authentication auth = new PreAuthenticatedAuthenticationToken("foobar", null);

		// FOO required; FOO supplied
		manager.setResourceRequestDetailsService(required(Collections.singleton("FOO")));
		manager.setTokenServices(supplied(Collections.singleton("FOO")));
		manager.authenticate(auth);

		// FOO still required; FOO and BAR supplied
		manager.setTokenServices(supplied(Collections.singleton("FOO BAR")));
		manager.authenticate(auth);

		// nothing required; FOO and BAR still supplied
		manager.setResourceRequestDetailsService(required(Collections.<String>emptySet()));
		manager.authenticate(auth);

		// nothing required; nothing supplied
		manager.setTokenServices(supplied(Collections.<String>emptySet()));
		manager.authenticate(auth);
	}

	@Test(expected = OAuth2AccessDeniedException.class)
	public void testCheckRequestDetails_insufficient_scope() {
		OAuth2AuthenticationManager manager = new OAuth2AuthenticationManager();
		manager.setResourceRequestDetailsService(required(Collections.singleton("FOOBAR")));
		manager.setTokenServices(supplied(Collections.<String>emptySet()));
		manager.authenticate(new PreAuthenticatedAuthenticationToken("foo", null));
	}

	@Test(expected = OAuth2AccessDeniedException.class)
	public void testCheckRequestDetails_not_found() {
		OAuth2AuthenticationManager manager = new OAuth2AuthenticationManager();
		manager.setResourceRequestDetailsService(required(null));
		manager.setTokenServices(supplied(Collections.<String>emptySet()));
		manager.authenticate(new PreAuthenticatedAuthenticationToken("foo", null));
	}

	private static ResourceRequestDetailsService required(Set<String> scope) {
		ResourceRequestDetailsService mockService = Mockito.mock(ResourceRequestDetailsService.class);

		if (scope != null) {
			ResourceRequestDetails mockDetails = Mockito.mock(ResourceRequestDetails.class);
			Mockito.when(mockDetails.getScope()).thenReturn(scope);
			Mockito.when(mockService.loadResourceRequestDetails(Mockito.anyString(),
							Mockito.anyString())).thenReturn(mockDetails);
		} else {
			Mockito.when(mockService.loadResourceRequestDetails(Mockito.anyString(),
							Mockito.anyString())).thenReturn(null);
		}

		return mockService;
	}

	private static ResourceServerTokenServices supplied(Set<String> scope) {
		OAuth2Authentication mockAuthentication = Mockito.mock(OAuth2Authentication.class);
		Mockito.when(mockAuthentication.getOAuth2Request())
						.thenReturn(RequestTokenFactory.createOAuth2Request("foo", false, scope));
		Mockito.when(mockAuthentication.getDetails()).thenReturn(Mockito.mock(OAuth2AuthenticationDetails.class));

		ResourceServerTokenServices mockServices = Mockito.mock(ResourceServerTokenServices.class);
		Mockito.when((mockServices.loadAuthentication(Mockito.anyString()))).thenReturn(mockAuthentication);

		return mockServices;
	}

}
