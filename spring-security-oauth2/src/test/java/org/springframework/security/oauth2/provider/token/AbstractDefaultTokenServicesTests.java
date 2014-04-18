/*
 * Copyright 2013-2014 the original author or authors.
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

package org.springframework.security.oauth2.provider.token;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.common.DefaultExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.ExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.RequestTokenFactory;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

/**
 * @author Dave Syer
 *
 */
public abstract class AbstractDefaultTokenServicesTests {

	private DefaultTokenServices services;

	private TokenStore tokenStore;

	@Before
	public void setUp() throws Exception {
		tokenStore = createTokenStore();
		services = new DefaultTokenServices();
		configureTokenServices(services);
	}

	@Test
	public void testClientSpecificRefreshTokenExpiry() throws Exception {
		getTokenServices().setRefreshTokenValiditySeconds(1000);
		getTokenServices().setClientDetailsService(new ClientDetailsService() {
			public ClientDetails loadClientByClientId(String clientId) throws OAuth2Exception {
				BaseClientDetails client = new BaseClientDetails();
				client.setRefreshTokenValiditySeconds(100);
				client.setAuthorizedGrantTypes(Arrays.asList("authorization_code", "refresh_token"));
				return client;
			}
		});
		OAuth2AccessToken accessToken = getTokenServices().createAccessToken(createAuthentication());
		DefaultExpiringOAuth2RefreshToken refreshToken = (DefaultExpiringOAuth2RefreshToken) accessToken
				.getRefreshToken();
		Date expectedExpiryDate = new Date(System.currentTimeMillis() + 102 * 1000L);
		assertTrue(expectedExpiryDate.after(refreshToken.getExpiration()));
	}

	@Test(expected = InvalidTokenException.class)
	public void testClientInvalidated() throws Exception {
		final AtomicBoolean deleted = new AtomicBoolean();
		getTokenServices().setClientDetailsService(new ClientDetailsService() {
			public ClientDetails loadClientByClientId(String clientId) throws OAuth2Exception {
				if (deleted.get()) {
					throw new ClientRegistrationException("No such client: " + clientId);
				}
				BaseClientDetails client = new BaseClientDetails();
				client.setRefreshTokenValiditySeconds(100);
				client.setAuthorizedGrantTypes(Arrays.asList("authorization_code", "refresh_token"));
				return client;
			}
		});
		OAuth2AccessToken token = getTokenServices()
				.createAccessToken(createAuthentication());
		deleted.set(true);
		OAuth2Authentication authentication = getTokenServices().loadAuthentication(token.getValue());
		assertNotNull(authentication.getOAuth2Request());
	}

	@Test(expected = InvalidGrantException.class)
	public void testRefreshedTokenInvalidWithWrongClient() throws Exception {
		ExpiringOAuth2RefreshToken expectedExpiringRefreshToken = (ExpiringOAuth2RefreshToken) getTokenServices()
				.createAccessToken(createAuthentication()).getRefreshToken();
		TokenRequest tokenRequest = new TokenRequest(Collections.singletonMap("client_id", "wrong"), "wrong", null,
				null);
		OAuth2AccessToken refreshedAccessToken = getTokenServices().refreshAccessToken(
				expectedExpiringRefreshToken.getValue(), tokenRequest);
		assertEquals("[read]", refreshedAccessToken.getScope().toString());
	}

	@Test
	public void testRefreshedTokenHasNarrowedScopes() throws Exception {
		ExpiringOAuth2RefreshToken expectedExpiringRefreshToken = (ExpiringOAuth2RefreshToken) getTokenServices()
				.createAccessToken(createAuthentication()).getRefreshToken();
		TokenRequest tokenRequest = new TokenRequest(Collections.singletonMap("client_id", "id"), "id",
				Collections.singleton("read"), null);
		OAuth2AccessToken refreshedAccessToken = getTokenServices().refreshAccessToken(
				expectedExpiringRefreshToken.getValue(), tokenRequest);
		assertEquals("[read]", refreshedAccessToken.getScope().toString());
	}

	@Test
	public void testTokenRevoked() throws Exception {
		OAuth2Authentication authentication = createAuthentication();
		OAuth2AccessToken original = getTokenServices().createAccessToken(authentication);
		getTokenStore().removeAccessToken(original);
		assertEquals(0, getTokenStore().findTokensByClientId(authentication.getOAuth2Request().getClientId()).size());
	}

	@Test
	public void testUnlimitedTokenExpiry() throws Exception {
		getTokenServices().setAccessTokenValiditySeconds(0);
		OAuth2AccessToken accessToken = getTokenServices().createAccessToken(createAuthentication());
		assertEquals(0, accessToken.getExpiresIn());
		assertEquals(null, accessToken.getExpiration());
	}

	@Test
	public void testDefaultTokenExpiry() throws Exception {
		getTokenServices().setAccessTokenValiditySeconds(100);
		OAuth2AccessToken accessToken = getTokenServices().createAccessToken(createAuthentication());
		assertTrue(100 >= accessToken.getExpiresIn());
	}

	@Test
	public void testClientSpecificTokenExpiry() throws Exception {
		getTokenServices().setAccessTokenValiditySeconds(1000);
		getTokenServices().setClientDetailsService(new ClientDetailsService() {
			public ClientDetails loadClientByClientId(String clientId) throws OAuth2Exception {
				BaseClientDetails client = new BaseClientDetails();
				client.setAccessTokenValiditySeconds(100);
				return client;
			}
		});
		OAuth2AccessToken accessToken = getTokenServices().createAccessToken(createAuthentication());
		assertTrue(100 >= accessToken.getExpiresIn());
	}

	@Test
	public void testRefreshedTokenHasScopes() throws Exception {
		ExpiringOAuth2RefreshToken expectedExpiringRefreshToken = (ExpiringOAuth2RefreshToken) getTokenServices()
				.createAccessToken(createAuthentication()).getRefreshToken();
		TokenRequest tokenRequest = new TokenRequest(Collections.singletonMap("client_id", "id"), "id", null, null);
		OAuth2AccessToken refreshedAccessToken = getTokenServices().refreshAccessToken(
				expectedExpiringRefreshToken.getValue(), tokenRequest);
		assertEquals("[read, write]", refreshedAccessToken.getScope().toString());
	}

	protected void configureTokenServices(DefaultTokenServices services) throws Exception {
		services.setTokenStore(tokenStore);
		services.setSupportRefreshToken(true);
		services.afterPropertiesSet();
	}

	protected abstract TokenStore createTokenStore();

	protected OAuth2Authentication createAuthentication() {
		return new OAuth2Authentication(RequestTokenFactory.createOAuth2Request(null, "id", null, false,
				new LinkedHashSet<String>(Arrays.asList("read", "write")), null, null, null, null),
				new TestAuthentication("test2", false));
	}

	protected TokenStore getTokenStore() {
		return tokenStore;
	}

	protected DefaultTokenServices getTokenServices() {
		return services;
	}

	protected static class TestAuthentication extends AbstractAuthenticationToken {

		private static final long serialVersionUID = 1L;

		private String principal;

		public TestAuthentication(String name, boolean authenticated) {
			super(null);
			setAuthenticated(authenticated);
			this.principal = name;
		}

		public Object getCredentials() {
			return null;
		}

		public Object getPrincipal() {
			return this.principal;
		}
	}

}
