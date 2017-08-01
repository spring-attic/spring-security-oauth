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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;

import org.junit.After;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.resource.BaseOAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.resource.UserRedirectRequiredException;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.common.DefaultExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.DefaultOAuth2RefreshToken;
import org.springframework.security.oauth2.common.ExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;

/**
 * @author Dave Syer
 * 
 */
public class AccessTokenProviderChainTests {

	private BaseOAuth2ProtectedResourceDetails resource;

	private DefaultOAuth2AccessToken accessToken = new DefaultOAuth2AccessToken("FOO");

	private DefaultOAuth2AccessToken refreshedToken = new DefaultOAuth2AccessToken("BAR");

	private UsernamePasswordAuthenticationToken user = new UsernamePasswordAuthenticationToken("foo", "bar",
			Arrays.asList(new SimpleGrantedAuthority("ROLE_USER")));

	private ClientTokenServices clientTokenServices = Mockito.mock(ClientTokenServices.class);

	public AccessTokenProviderChainTests() {
		resource = new BaseOAuth2ProtectedResourceDetails();
		resource.setId("resource");
	}

	@After
	public void close() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void testSunnyDay() throws Exception {
		AccessTokenProviderChain chain = new AccessTokenProviderChain(Arrays.asList(new StubAccessTokenProvider()));
		AccessTokenRequest request = new DefaultAccessTokenRequest();
		SecurityContextHolder.getContext().setAuthentication(user);
		OAuth2AccessToken token = chain.obtainAccessToken(resource, request);
		assertNotNull(token);
	}

	@Test
	public void testSunnyDayWithTokenServicesGet() throws Exception {
		AccessTokenProviderChain chain = new AccessTokenProviderChain(Collections.<AccessTokenProvider> emptyList());
		when(clientTokenServices.getAccessToken(resource, user)).thenReturn(accessToken);
		chain.setClientTokenServices(clientTokenServices);
		AccessTokenRequest request = new DefaultAccessTokenRequest();
		SecurityContextHolder.getContext().setAuthentication(user);
		OAuth2AccessToken token = chain.obtainAccessToken(resource, request);
		assertEquals(accessToken, token);
		Mockito.verify(clientTokenServices).saveAccessToken(resource, user, token);
	}

	@Test
	public void testSunnyDayWithTokenServicesSave() throws Exception {
		AccessTokenProviderChain chain = new AccessTokenProviderChain(Arrays.asList(new StubAccessTokenProvider()));
		chain.setClientTokenServices(clientTokenServices);
		AccessTokenRequest request = new DefaultAccessTokenRequest();
		SecurityContextHolder.getContext().setAuthentication(user);
		OAuth2AccessToken token = chain.obtainAccessToken(resource, request);
		assertNotNull(token);
		Mockito.verify(clientTokenServices).saveAccessToken(resource, user, token);
	}

	@Test
	public void testSunnyDayClientCredentialsWithTokenServicesSave() throws Exception {
		AccessTokenProviderChain chain = new AccessTokenProviderChain(Arrays.asList(new StubAccessTokenProvider()));
		chain.setClientTokenServices(clientTokenServices);
		AccessTokenRequest request = new DefaultAccessTokenRequest();
		resource = new ClientCredentialsResourceDetails();
		resource.setId("resource");
		OAuth2AccessToken token = chain.obtainAccessToken(resource, request);
		assertNotNull(token);
		Mockito.verify(clientTokenServices).saveAccessToken(resource, null, token);
	}

	@Test
	public void testSunnyDayWithExpiredToken() throws Exception {
		AccessTokenProviderChain chain = new AccessTokenProviderChain(Arrays.asList(new StubAccessTokenProvider()));
		accessToken.setExpiration(new Date(System.currentTimeMillis() - 1000));
		AccessTokenRequest request = new DefaultAccessTokenRequest();
		request.setExistingToken(accessToken);
		SecurityContextHolder.getContext().setAuthentication(user);
		OAuth2AccessToken token = chain.obtainAccessToken(resource, request);
		assertNotNull(token);
	}

	@Test
	public void testSunnyDayWithExpiredTokenAndTokenServices() throws Exception {
		AccessTokenProviderChain chain = new AccessTokenProviderChain(Arrays.asList(new StubAccessTokenProvider()));
		chain.setClientTokenServices(clientTokenServices);
		accessToken.setExpiration(new Date(System.currentTimeMillis() - 1000));
		when(clientTokenServices.getAccessToken(resource, user)).thenReturn(accessToken);
		AccessTokenRequest request = new DefaultAccessTokenRequest();
		SecurityContextHolder.getContext().setAuthentication(user);
		OAuth2AccessToken token = chain.obtainAccessToken(resource, request);
		assertNotNull(token);
		Mockito.verify(clientTokenServices).removeAccessToken(resource, user);
		Mockito.verify(clientTokenServices).saveAccessToken(resource, user, token);
	}

	@Test
	public void testSunnyDayWIthExpiredTokenAndValidRefreshToken() throws Exception {
		AccessTokenProviderChain chain = new AccessTokenProviderChain(Arrays.asList(new StubAccessTokenProvider()));
		accessToken.setExpiration(new Date(System.currentTimeMillis() - 1000));
		accessToken.setRefreshToken(new DefaultOAuth2RefreshToken("EXP"));
		AccessTokenRequest request = new DefaultAccessTokenRequest();
		request.setExistingToken(accessToken);
		SecurityContextHolder.getContext().setAuthentication(user);
		OAuth2AccessToken token = chain.obtainAccessToken(resource, request);
		assertNotNull(token);
	}

	@Test(expected = InvalidTokenException.class)
	public void testSunnyDayWIthExpiredTokenAndExpiredRefreshToken() throws Exception {
		AccessTokenProviderChain chain = new AccessTokenProviderChain(Arrays.asList(new StubAccessTokenProvider()));
		accessToken.setExpiration(new Date(System.currentTimeMillis() - 1000));
		DefaultOAuth2RefreshToken refreshToken = new DefaultExpiringOAuth2RefreshToken("EXP",
				new Date(System.currentTimeMillis() - 1000));
		accessToken.setRefreshToken(refreshToken);
		AccessTokenRequest request = new DefaultAccessTokenRequest();
		request.setExistingToken(accessToken);
		SecurityContextHolder.getContext().setAuthentication(user);
		OAuth2AccessToken token = chain.obtainAccessToken(resource, request);
		assertNotNull(token);
	}

	@Test
	public void testSunnyDayWithExpiredTokenAndExpiredRefreshTokenForClientCredentialsResource() {
		resource = new ClientCredentialsResourceDetails();
		resource.setId("resource");
		AccessTokenProviderChain chain = new AccessTokenProviderChain(Arrays.asList(new StubAccessTokenProvider()));
		accessToken.setExpiration(new Date(System.currentTimeMillis() - 1000));
		DefaultOAuth2RefreshToken refreshToken = new DefaultExpiringOAuth2RefreshToken("EXP",
				new Date(System.currentTimeMillis() - 1000));
		accessToken.setRefreshToken(refreshToken);
		AccessTokenRequest request = new DefaultAccessTokenRequest();
		request.setExistingToken(accessToken);
		SecurityContextHolder.getContext().setAuthentication(user);
		OAuth2AccessToken token = chain.obtainAccessToken(resource, request);
		assertNotNull(token);
		assertSame(accessToken, token);
		assertSame(refreshToken, token.getRefreshToken());
	}

	@Test
	public void testMissingSecurityContext() throws Exception {
		AccessTokenProviderChain chain = new AccessTokenProviderChain(Arrays.asList(new StubAccessTokenProvider()));
		AccessTokenRequest request = new DefaultAccessTokenRequest();
		OAuth2AccessToken token = chain.obtainAccessToken(resource, request);
		assertNotNull(token);
		// If there is no authentication to store it with a token is still acquired if
		// possible
	}

	@Test(expected = InsufficientAuthenticationException.class)
	public void testAnonymousUser() throws Exception {
		AccessTokenProviderChain chain = new AccessTokenProviderChain(Arrays.asList(new StubAccessTokenProvider()));
		SecurityContextHolder.getContext()
				.setAuthentication(new AnonymousAuthenticationToken("foo", "bar", user.getAuthorities()));
		AccessTokenRequest request = new DefaultAccessTokenRequest();
		OAuth2AccessToken token = chain.obtainAccessToken(resource, request);
		assertNotNull(token);
	}

	@Test(expected = UserRedirectRequiredException.class)
	public void testRequiresAuthenticationButRedirected() throws Exception {
		final AccessTokenRequest request = new DefaultAccessTokenRequest();
		AccessTokenProviderChain chain = new AccessTokenProviderChain(Arrays.asList(new StubAccessTokenProvider() {
			@Override
			public OAuth2AccessToken obtainAccessToken(OAuth2ProtectedResourceDetails details,
					AccessTokenRequest parameters) throws UserRedirectRequiredException, AccessDeniedException {
				throw new UserRedirectRequiredException("redirect test", request.toSingleValueMap());
			}
		}));
		OAuth2AccessToken token = chain.obtainAccessToken(resource, request);
		assertNotNull(token);
	}

	@Test
	public void testRefreshAccessTokenReplacingNullValue() throws Exception {
		DefaultOAuth2AccessToken accessToken = getExpiredToken();
		DefaultOAuth2AccessToken refreshedAccessToken = new DefaultOAuth2AccessToken("refreshed-access-token");
		AccessTokenProviderChain chain = getTokenProvider(accessToken, refreshedAccessToken);

		SecurityContextHolder.getContext().setAuthentication(user);

		// Obtain a new Access Token
		AuthorizationCodeResourceDetails resource = new AuthorizationCodeResourceDetails();
		AccessTokenRequest request = new DefaultAccessTokenRequest();
		OAuth2AccessToken newAccessToken = chain.refreshAccessToken(resource, accessToken.getRefreshToken(), request);
		// gh-712
		assertEquals(newAccessToken.getRefreshToken(), accessToken.getRefreshToken());
	}

	@Test
	public void testRefreshAccessTokenKeepingOldValue() throws Exception {
		DefaultOAuth2AccessToken accessToken = getExpiredToken();
		DefaultOAuth2AccessToken refreshedAccessToken = new DefaultOAuth2AccessToken("refreshed-access-token");
		refreshedAccessToken.setRefreshToken(new DefaultOAuth2RefreshToken("other-refresh-token"));
		AccessTokenProviderChain chain = getTokenProvider(accessToken, refreshedAccessToken);

		SecurityContextHolder.getContext().setAuthentication(user);

		// Obtain a new Access Token
		AuthorizationCodeResourceDetails resource = new AuthorizationCodeResourceDetails();
		AccessTokenRequest request = new DefaultAccessTokenRequest();
		OAuth2AccessToken newAccessToken = chain.refreshAccessToken(resource, accessToken.getRefreshToken(), request);
		// gh-816
		assertEquals(newAccessToken.getRefreshToken(), refreshedAccessToken.getRefreshToken());
	}

	private DefaultOAuth2AccessToken getExpiredToken() {
		Calendar tokenExpiry = Calendar.getInstance();
		DefaultOAuth2AccessToken accessToken = new DefaultOAuth2AccessToken("access-token");
		accessToken.setExpiration(tokenExpiry.getTime());
		accessToken.setRefreshToken(new DefaultOAuth2RefreshToken("refresh-token"));
		return accessToken;
	}

	// gh-712
	@Test
	public void testRefreshAccessTokenTwicePreserveRefreshToken() throws Exception {
		DefaultOAuth2AccessToken accessToken = getExpiredToken();
		DefaultOAuth2AccessToken expectedRefreshedAccessToken = new DefaultOAuth2AccessToken("refreshed-access-token");
		expectedRefreshedAccessToken.setExpiration(accessToken.getExpiration());

		AccessTokenProviderChain chain = getTokenProvider(accessToken, expectedRefreshedAccessToken);

		SecurityContextHolder.getContext().setAuthentication(user);

		// Obtain a new Access Token
		AuthorizationCodeResourceDetails resource = new AuthorizationCodeResourceDetails();
		AccessTokenRequest request = new DefaultAccessTokenRequest();
		OAuth2AccessToken tokenResult = chain.obtainAccessToken(resource, request);
		assertEquals(accessToken, tokenResult);

		// Obtain the 1st Refreshed Access Token
		Calendar tokenExpiry = Calendar.getInstance();
		tokenExpiry.setTime(tokenResult.getExpiration());
		tokenExpiry.add(Calendar.MINUTE, -1);
		DefaultOAuth2AccessToken.class.cast(tokenResult).setExpiration(tokenExpiry.getTime()); // Expire
		request = new DefaultAccessTokenRequest();
		request.setExistingToken(tokenResult);
		tokenResult = chain.obtainAccessToken(resource, request);
		assertEquals(expectedRefreshedAccessToken, tokenResult);

		// Obtain the 2nd Refreshed Access Token
		tokenExpiry.setTime(tokenResult.getExpiration());
		tokenExpiry.add(Calendar.MINUTE, -1);
		DefaultOAuth2AccessToken.class.cast(tokenResult).setExpiration(tokenExpiry.getTime()); // Expire
		request = new DefaultAccessTokenRequest();
		request.setExistingToken(tokenResult);
		tokenResult = chain.obtainAccessToken(resource, request);
		assertEquals(expectedRefreshedAccessToken, tokenResult);
	}

	private AccessTokenProviderChain getTokenProvider(DefaultOAuth2AccessToken accessToken,
			DefaultOAuth2AccessToken refreshedAccessToken) {
		AccessTokenProvider accessTokenProvider = new AuthorizationCodeAccessTokenProvider();
		accessTokenProvider = spy(accessTokenProvider);
		doReturn(accessToken).when(accessTokenProvider).obtainAccessToken(any(OAuth2ProtectedResourceDetails.class),
				any(AccessTokenRequest.class));
		doReturn(refreshedAccessToken).when(accessTokenProvider).refreshAccessToken(
				any(OAuth2ProtectedResourceDetails.class), any(OAuth2RefreshToken.class),
				any(AccessTokenRequest.class));
		AccessTokenProviderChain chain = new AccessTokenProviderChain(Arrays.asList(accessTokenProvider));
		return chain;
	}

	private class StubAccessTokenProvider implements AccessTokenProvider {
		public OAuth2AccessToken obtainAccessToken(OAuth2ProtectedResourceDetails details,
				AccessTokenRequest parameters) throws UserRedirectRequiredException, AccessDeniedException {
			return accessToken;
		}

		public boolean supportsRefresh(OAuth2ProtectedResourceDetails resource) {
			return true;
		}

		public OAuth2AccessToken refreshAccessToken(OAuth2ProtectedResourceDetails resource,
				OAuth2RefreshToken refreshToken, AccessTokenRequest request) throws UserRedirectRequiredException {
			if (refreshToken instanceof ExpiringOAuth2RefreshToken) {
				if (((ExpiringOAuth2RefreshToken) refreshToken).getExpiration().getTime() < System
						.currentTimeMillis()) {
					// this is what a real provider would do (re-throw a remote exception)
					throw new InvalidTokenException("Expired refresh token");
				}
			}
			return refreshedToken;
		}

		public boolean supportsResource(OAuth2ProtectedResourceDetails resource) {
			return true;
		}
	}

}
