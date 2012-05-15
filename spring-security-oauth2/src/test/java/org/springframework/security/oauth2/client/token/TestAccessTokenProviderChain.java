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
package org.springframework.security.oauth2.client.token;

import static org.junit.Assert.assertNotNull;

import java.util.Arrays;

import org.junit.After;
import org.junit.Test;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.UserRedirectRequiredException;
import org.springframework.security.oauth2.client.resource.BaseOAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

/**
 * @author Dave Syer
 * 
 */
public class TestAccessTokenProviderChain {

	private BaseOAuth2ProtectedResourceDetails resource;

	private UsernamePasswordAuthenticationToken user = new UsernamePasswordAuthenticationToken("foo", "bar",
			Arrays.asList(new SimpleGrantedAuthority("ROLE_USER")));

	public TestAccessTokenProviderChain() {
		resource = new BaseOAuth2ProtectedResourceDetails();
		resource.setId("resource");
	}

	@After
	public void close() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void testSunnyDay() throws Exception {
		AccessTokenProviderChain chain = new AccessTokenProviderChain(
				Arrays.<AccessTokenProvider> asList(new StubAccessTokenProvider()));
		AccessTokenRequest request = new DefaultAccessTokenRequest();
		SecurityContextHolder.getContext().setAuthentication(user);
		OAuth2AccessToken token = chain.obtainAccessToken(resource, request);
		assertNotNull(token);
	}

	@Test
	public void testMissingSecurityContext() throws Exception {
		AccessTokenProviderChain chain = new AccessTokenProviderChain(
				Arrays.<AccessTokenProvider> asList(new StubAccessTokenProvider()));
		AccessTokenRequest request = new DefaultAccessTokenRequest();
		OAuth2AccessToken token = chain.obtainAccessToken(resource, request);
		assertNotNull(token);
		// If there is no authentication to store it with a token is still acquired if possible
	}

	@Test(expected = InsufficientAuthenticationException.class)
	public void testAnonymousUser() throws Exception {
		AccessTokenProviderChain chain = new AccessTokenProviderChain(
				Arrays.<AccessTokenProvider> asList(new StubAccessTokenProvider()));
		SecurityContextHolder.getContext().setAuthentication(
				new AnonymousAuthenticationToken("foo", "bar", user.getAuthorities()));
		AccessTokenRequest request = new DefaultAccessTokenRequest();
		OAuth2AccessToken token = chain.obtainAccessToken(resource, request);
		assertNotNull(token);
	}

	@Test(expected = UserRedirectRequiredException.class)
	public void testRequiresAuthenticationButRedirected() throws Exception {
		final AccessTokenRequest request = new DefaultAccessTokenRequest();
		AccessTokenProviderChain chain = new AccessTokenProviderChain(
				Arrays.<AccessTokenProvider> asList(new StubAccessTokenProvider() {
					@Override
					public OAuth2AccessToken obtainAccessToken(OAuth2ProtectedResourceDetails details,
							AccessTokenRequest parameters) throws UserRedirectRequiredException, AccessDeniedException {
						throw new UserRedirectRequiredException("redirect test", request.toSingleValueMap());
					}
				}));
		OAuth2AccessToken token = chain.obtainAccessToken(resource, request);
		assertNotNull(token);
	}

	private static class StubAccessTokenProvider implements AccessTokenProvider {
		public OAuth2AccessToken obtainAccessToken(OAuth2ProtectedResourceDetails details,
				AccessTokenRequest parameters) throws UserRedirectRequiredException, AccessDeniedException {
			return new DefaultOAuth2AccessToken("FOO");
		}

		public boolean supportsRefresh(OAuth2ProtectedResourceDetails resource) {
			return false;
		}
		
		public OAuth2AccessToken refreshAccessToken(OAuth2ProtectedResourceDetails resource,
				OAuth2RefreshToken refreshToken, AccessTokenRequest request) throws UserRedirectRequiredException {
			return null;
		}

		public boolean supportsResource(OAuth2ProtectedResourceDetails resource) {
			return true;
		}
	}

}
