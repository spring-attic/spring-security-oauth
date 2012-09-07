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

import javax.servlet.ServletException;

import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.security.oauth2.client.http.AccessTokenRequiredException;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.provider.DefaultAuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;

public class TestOAuth2ClientAuthenticationProcessingFilter {

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
		this.authentication = new OAuth2Authentication(new DefaultAuthorizationRequest("client", Arrays.asList("read",
				"write")), null);
		Mockito.when(tokenServices.loadAuthentication("FOO")).thenReturn(authentication);
		Authentication authentication = filter.attemptAuthentication(null, null);
		assertEquals(this.authentication, authentication);
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
