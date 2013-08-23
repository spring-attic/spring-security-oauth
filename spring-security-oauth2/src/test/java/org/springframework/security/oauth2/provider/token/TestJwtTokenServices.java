/*
 * Cloud Foundry 2012.02.03 Beta
 * Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
 *
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 *
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 */

package org.springframework.security.oauth2.provider.token;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.MacSigner;
import org.springframework.security.oauth2.common.DefaultExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.ExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.BaseClientDetails;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * @author Dave Syer
 * 
 */
public class TestJwtTokenServices {

	private JwtTokenServices services = new JwtTokenServices();

	private JwtTokenEnhancer enhancer;

	@Before
	public void init() throws Exception {
		services.setVerifierKey("FOO");
		services.setSigningKey("FOO");
		services.afterPropertiesSet();
		enhancer = (JwtTokenEnhancer) ReflectionTestUtils.getField(services, "jwtTokenEnhancer");
		services.setSupportRefreshToken(true);
	}

	@Test
	public void testReadAccessToken() throws Exception {
		String token = JwtHelper.encode("{\"client_id\":\"client\"}", new MacSigner("FOO")).getEncoded();
		OAuth2AccessToken accessToken = services.readAccessToken(token);
		assertEquals(token, accessToken.getValue());
	}

	@Test
	public void testLoadAuthentication() throws Exception {
		String token = JwtHelper.encode("{\"client_id\":\"client\"}", new MacSigner("FOO")).getEncoded();
		OAuth2Authentication authentication = services.loadAuthentication(token);
		assertEquals(null, authentication.getUserAuthentication());
		assertEquals("client", authentication.getOAuth2Request().getClientId());
	}

	@Test
	public void testTokenEnhancerUpdatesTokens() throws Exception {
		services.setTokenEnhancer(new TokenEnhancer() {
			public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
				DefaultOAuth2AccessToken result = new DefaultOAuth2AccessToken(accessToken);
				ExpiringOAuth2RefreshToken refreshToken = new DefaultExpiringOAuth2RefreshToken("testToken", new Date(
						System.currentTimeMillis() + 100000));
				result.setRefreshToken(refreshToken);
				return result;
			}
		});
		OAuth2Authentication authentication = createAuthentication();
		OAuth2AccessToken original = services.createAccessToken(authentication);
		String result = enhancer.encode(original, authentication);
		assertEquals(original.getValue(), result);
	}

	@Test
	public void testJwtTokenEnhancerIdempotent() throws Exception {
		OAuth2Authentication authentication = createAuthentication();
		OAuth2AccessToken original = services.createAccessToken(authentication);
		services.setTokenEnhancer(enhancer);
		OAuth2AccessToken updated = services.createAccessToken(authentication);
		assertEquals(original.getValue(), updated.getValue());
	}

	@Test
	public void testRefreshedTokenIsEnhanced() throws Exception {
		services.setTokenEnhancer(new TokenEnhancer() {
			public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
				DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken(accessToken);
				token.setAdditionalInformation(Collections.<String, Object> singletonMap("foo", "bar"));
				return token;
			}
		});

		OAuth2AccessToken accessToken = services.createAccessToken(createAuthentication());
		assertEquals("bar", accessToken.getAdditionalInformation().get("foo"));
		OAuth2AccessToken refreshedAccessToken = services.refreshAccessToken(accessToken.getRefreshToken().getValue(),
				new TokenRequest(null, "id", null, null));
		assertEquals("bar", refreshedAccessToken.getAdditionalInformation().get("foo"));
	}

	@Test
	public void testRefreshedTokenHasScopes() throws Exception {
		ExpiringOAuth2RefreshToken expectedExpiringRefreshToken = (ExpiringOAuth2RefreshToken) services
				.createAccessToken(createAuthentication()).getRefreshToken();
		OAuth2AccessToken refreshedAccessToken = services.refreshAccessToken(expectedExpiringRefreshToken.getValue(),
				new TokenRequest(null, "id", null, null));
		assertEquals("[read]", refreshedAccessToken.getScope().toString());
	}

	@Test(expected = InvalidGrantException.class)
	public void testRefreshedTokenInvalidWithWrongClient() throws Exception {
		ExpiringOAuth2RefreshToken expectedExpiringRefreshToken = (ExpiringOAuth2RefreshToken) services
				.createAccessToken(createAuthentication()).getRefreshToken();
		OAuth2AccessToken refreshedAccessToken = services.refreshAccessToken(expectedExpiringRefreshToken.getValue(),
				new TokenRequest(null, "wrong", null, null));
		assertEquals("[read]", refreshedAccessToken.getScope().toString());
	}

	@Test
	public void testUnlimitedTokenExpiry() throws Exception {
		services.setAccessTokenValiditySeconds(0);
		OAuth2AccessToken accessToken = services.createAccessToken(createAuthentication());
		assertEquals(0, accessToken.getExpiresIn());
		assertEquals(null, accessToken.getExpiration());
	}

	@Test
	public void testDefaultTokenExpiry() throws Exception {
		services.setAccessTokenValiditySeconds(100);
		OAuth2AccessToken accessToken = services.createAccessToken(createAuthentication());
		assertTrue(100 >= accessToken.getExpiresIn());
	}

	@Test
	public void testClientSpecificTokenExpiry() throws Exception {
		services.setAccessTokenValiditySeconds(1000);
		services.setClientDetailsService(new ClientDetailsService() {
			public ClientDetails loadClientByClientId(String clientId) throws OAuth2Exception {
				BaseClientDetails client = new BaseClientDetails();
				client.setAccessTokenValiditySeconds(100);
				return client;
			}
		});
		OAuth2AccessToken accessToken = services.createAccessToken(createAuthentication());
		assertTrue(100 >= accessToken.getExpiresIn());
	}

	@Test
	public void testClientSpecificRefreshTokenExpiry() throws Exception {
		services.setRefreshTokenValiditySeconds(1000);
		services.setClientDetailsService(new ClientDetailsService() {
			public ClientDetails loadClientByClientId(String clientId) throws OAuth2Exception {
				BaseClientDetails client = new BaseClientDetails();
				client.setRefreshTokenValiditySeconds(100);
				client.setAuthorizedGrantTypes(Arrays.asList("authorization_code", "refresh_token"));
				return client;
			}
		});
		OAuth2AccessToken accessToken = services.createAccessToken(createAuthentication());
		DefaultExpiringOAuth2RefreshToken refreshToken = (DefaultExpiringOAuth2RefreshToken) accessToken
				.getRefreshToken();
		Date expectedExpiryDate = new Date(System.currentTimeMillis() + 102 * 1000L);
		assertTrue(expectedExpiryDate.after(refreshToken.getExpiration()));
	}

	@Test
	public void testOneAccessTokenPerAuthentication() throws Exception {
		OAuth2Authentication authentication = createAuthentication();
		OAuth2AccessToken first = services.createAccessToken(authentication);
		OAuth2AccessToken second = services.createAccessToken(authentication);
		assertEquals(first, second);
	}

	@Test
	public void testOneAccessTokenPerUniqueAuthentication() throws Exception {
		String clientId = "id";
		services.createAccessToken(new OAuth2Authentication(
				createOAuth2Request(clientId, Collections.singleton("read")), new TestAuthentication("test2", false)));
		services.createAccessToken(new OAuth2Authentication(createOAuth2Request(clientId,
				Collections.singleton("write")), new TestAuthentication("test2", false)));
	}

	@Test
	public void testRefreshTokenMaintainsState() throws Exception {
		services.setSupportRefreshToken(true);
		OAuth2AccessToken accessToken = services.createAccessToken(createAuthentication());
		OAuth2RefreshToken expectedExpiringRefreshToken = accessToken.getRefreshToken();
		OAuth2AccessToken refreshedAccessToken = services.refreshAccessToken(expectedExpiringRefreshToken.getValue(),
				new TokenRequest(null, "id", null, null));
		assertNotNull(refreshedAccessToken);
	}

	@Test
	public void testNotReuseRefreshTokenMaintainsState() throws Exception {
		services.setSupportRefreshToken(true);
		services.setReuseRefreshToken(false);
		OAuth2AccessToken accessToken = services.createAccessToken(createAuthentication());
		OAuth2RefreshToken expectedExpiringRefreshToken = accessToken.getRefreshToken();
		OAuth2AccessToken refreshedAccessToken = services.refreshAccessToken(expectedExpiringRefreshToken.getValue(),
				new TokenRequest(null, "id", null, null));
		assertNotNull(refreshedAccessToken);
	}

	private OAuth2Authentication createAuthentication() {
		return new OAuth2Authentication(createOAuth2Request("id", Collections.singleton("read")),
				new TestAuthentication("test2", false));
	}

	private OAuth2Request createOAuth2Request(String clientId, Set<String> scope) {
		return new OAuth2Request(Collections.<String, String> emptyMap(), clientId, null, true, scope, null, null,
				null, null);
	}

	protected static class TestAuthentication extends AbstractAuthenticationToken {
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
