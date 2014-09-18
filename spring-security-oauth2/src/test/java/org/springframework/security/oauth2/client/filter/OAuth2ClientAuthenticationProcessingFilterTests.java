/*
 * Copyright 2010-2012 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.client.filter;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import javax.servlet.ServletException;

import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.security.oauth2.client.http.AccessTokenRequiredException;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.RequestTokenFactory;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;

public class OAuth2ClientAuthenticationProcessingFilterTests {

	private OAuth2ClientAuthenticationProcessingFilter filter = new OAuth2ClientAuthenticationProcessingFilter(
			"/some/url");

	private ResourceServerTokenServices tokenServices = Mockito.mock(ResourceServerTokenServices.class);

	private OAuth2RestOperations restTemplate = Mockito.mock(OAuth2RestOperations.class);

	private OAuth2Authentication authentication;

	@Test
	public void testAuthentication() throws Exception {
		filter.setRestTemplate(restTemplate);
		filter.setTokenServices(tokenServices);
		Mockito.when(restTemplate.getAccessToken()).thenReturn(new DefaultOAuth2AccessToken("FOO"));
		Set<String> scopes = new HashSet<String>();
		scopes.addAll(Arrays.asList("read", "write"));
		OAuth2Request storedOAuth2Request = RequestTokenFactory.createOAuth2Request("client", false, scopes);
		this.authentication = new OAuth2Authentication(storedOAuth2Request, null);
		Mockito.when(tokenServices.loadAuthentication("FOO")).thenReturn(authentication);
		Authentication authentication = filter.attemptAuthentication(new MockHttpServletRequest(), null);
		assertEquals(this.authentication, authentication);
		Mockito.verify(restTemplate, Mockito.times(1)).getAccessToken();
	}

	@Test
	public void testSuccessfulAuthentication() throws Exception {
		filter.setRestTemplate(restTemplate);
		Set<String> scopes = new HashSet<String>();
		scopes.addAll(Arrays.asList("read", "write"));
		OAuth2Request storedOAuth2Request = RequestTokenFactory.createOAuth2Request("client", false, scopes);
		this.authentication = new OAuth2Authentication(storedOAuth2Request, null);
		filter.successfulAuthentication(new MockHttpServletRequest(), new MockHttpServletResponse(), null, authentication);
		Mockito.verify(restTemplate, Mockito.times(1)).getAccessToken();
	}

	@Test
	public void testUnsuccessfulAuthentication() throws IOException, ServletException {
		try {
			filter.unsuccessfulAuthentication(null, null, new AccessTokenRequiredException("testing", null));
			fail("AccessTokenRedirectException must be thrown");
		}
		catch (AccessTokenRequiredException ex) {

		}
	}
}
