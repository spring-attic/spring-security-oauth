package org.springframework.security.oauth2.provider.token;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.Collections;
import java.util.Date;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.common.DefaultExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.ExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.BaseClientDetails;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.DefaultAuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

/**
 * @author Dave Syer
 * 
 */
public abstract class AbstractTestDefaultTokenServices {

	private DefaultTokenServices services;

	private TokenStore tokenStore;

	@Before
	public void setUp() throws Exception {
		tokenStore = createTokenStore();
		services = new DefaultTokenServices();
		getTokenServices().setTokenStore(tokenStore);
		getTokenServices().afterPropertiesSet();
		getTokenServices().setSupportRefreshToken(true);
	}

	protected abstract TokenStore createTokenStore();

	@Test
	public void testTokenEnhancerUpdatesStoredTokens() throws Exception {
		OAuth2Authentication expectedAuthentication = new OAuth2Authentication(new DefaultAuthorizationRequest("id",
				Collections.singleton("read")), new TestAuthentication("test2", false));
		DefaultTokenServices tokenServices = getTokenServices();
		tokenServices.setTokenEnhancer(new TokenEnhancer() {
			public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
				DefaultOAuth2AccessToken result = new DefaultOAuth2AccessToken(accessToken);
				ExpiringOAuth2RefreshToken refreshToken = new DefaultExpiringOAuth2RefreshToken("testToken", new Date(
						System.currentTimeMillis() + 100000));
				result.setRefreshToken(refreshToken);
				return result;
			}
		});
		OAuth2AccessToken original = tokenServices.createAccessToken(expectedAuthentication);
		OAuth2AccessToken result = tokenStore.getAccessToken(expectedAuthentication);
		assertEquals(original, result);
	}

	@Test
	public void testRefreshedTokenHasScopes() throws Exception {
		ExpiringOAuth2RefreshToken expectedExpiringRefreshToken = new DefaultExpiringOAuth2RefreshToken("testToken",
				new Date(System.currentTimeMillis() + 100000));
		OAuth2Authentication expectedAuthentication = new OAuth2Authentication(new DefaultAuthorizationRequest("id",
				Collections.singleton("read")), new TestAuthentication("test2", false));
		tokenStore.storeRefreshToken(expectedExpiringRefreshToken, expectedAuthentication);
		OAuth2AccessToken refreshedAccessToken = getTokenServices().refreshAccessToken(
				expectedExpiringRefreshToken.getValue(), null);
		assertEquals("[read]", refreshedAccessToken.getScope().toString());
	}

	@Test
	public void testUnlimitedTokenExpiry() throws Exception {
		getTokenServices().setAccessTokenValiditySeconds(0);
		OAuth2Authentication expectedAuthentication = new OAuth2Authentication(new DefaultAuthorizationRequest("id",
				Collections.singleton("read")), new TestAuthentication("test2", false));
		OAuth2AccessToken accessToken = getTokenServices().createAccessToken(expectedAuthentication);
		assertEquals(0, accessToken.getExpiresIn());
		assertEquals(null, accessToken.getExpiration());
	}

	@Test
	public void testDefaultTokenExpiry() throws Exception {
		getTokenServices().setAccessTokenValiditySeconds(100);
		OAuth2Authentication expectedAuthentication = new OAuth2Authentication(new DefaultAuthorizationRequest("id",
				Collections.singleton("read")), new TestAuthentication("test2", false));
		OAuth2AccessToken accessToken = getTokenServices().createAccessToken(expectedAuthentication);
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
		OAuth2Authentication expectedAuthentication = new OAuth2Authentication(new DefaultAuthorizationRequest("id",
				Collections.singleton("read")), new TestAuthentication("test2", false));
		OAuth2AccessToken accessToken = getTokenServices().createAccessToken(expectedAuthentication);
		assertTrue(100 >= accessToken.getExpiresIn());
	}

	@Test
	public void testClientSpecificRefreshTokenExpiry() throws Exception {
		getTokenServices().setRefreshTokenValiditySeconds(1000);
		getTokenServices().setClientDetailsService(new ClientDetailsService() {
			public ClientDetails loadClientByClientId(String clientId) throws OAuth2Exception {
				BaseClientDetails client = new BaseClientDetails();
				client.setRefreshTokenValiditySeconds(100);
				return client;
			}
		});
		OAuth2Authentication expectedAuthentication = new OAuth2Authentication(new DefaultAuthorizationRequest("id",
				Collections.singleton("read")), new TestAuthentication("test2", false));
		OAuth2AccessToken accessToken = getTokenServices().createAccessToken(expectedAuthentication);
		DefaultExpiringOAuth2RefreshToken refreshToken = (DefaultExpiringOAuth2RefreshToken) accessToken
				.getRefreshToken();
		Date expectedExpiryDate = new Date(System.currentTimeMillis() + 102 * 1000L);
		assertTrue(expectedExpiryDate.after(refreshToken.getExpiration()));
	}

	@Test
	public void testOneAccessTokenPerAuthentication() throws Exception {
		OAuth2Authentication authentication = new OAuth2Authentication(new DefaultAuthorizationRequest("id",
				Collections.singleton("read")), new TestAuthentication("test2", false));
		OAuth2AccessToken first = getTokenServices().createAccessToken(authentication);
		assertEquals(1, getAccessTokenCount());
		assertEquals(1, getRefreshTokenCount());
		OAuth2AccessToken second = getTokenServices().createAccessToken(authentication);
		assertEquals(first, second);
		assertEquals(1, getAccessTokenCount());
		assertEquals(1, getRefreshTokenCount());
	}

	@Test
	public void testOneAccessTokenPerUniqueAuthentication() throws Exception {
		getTokenServices().createAccessToken(
				new OAuth2Authentication(new DefaultAuthorizationRequest("id", Collections.singleton("read")),
						new TestAuthentication("test2", false)));
		assertEquals(1, getAccessTokenCount());
		getTokenServices().createAccessToken(
				new OAuth2Authentication(new DefaultAuthorizationRequest("id", Collections.singleton("write")),
						new TestAuthentication("test2", false)));
		assertEquals(2, getAccessTokenCount());
	}

	@Test
	public void testRefreshTokenMaintainsState() throws Exception {
		OAuth2Authentication expectedAuthentication = new OAuth2Authentication(new DefaultAuthorizationRequest("id",
				Collections.singleton("read")), new TestAuthentication("test2", false));
		getTokenServices().setSupportRefreshToken(true);
		OAuth2AccessToken accessToken = getTokenServices().createAccessToken(expectedAuthentication);
		OAuth2RefreshToken expectedExpiringRefreshToken = accessToken.getRefreshToken();
		OAuth2AccessToken refreshedAccessToken = getTokenServices().refreshAccessToken(
				expectedExpiringRefreshToken.getValue(), null);
		assertNotNull(refreshedAccessToken);
		assertEquals(1, getAccessTokenCount());
	}

	@Test
	public void testNotReuseRefreshTokenMaintainsState() throws Exception {
		OAuth2Authentication expectedAuthentication = new OAuth2Authentication(new DefaultAuthorizationRequest("id",
				Collections.singleton("read")), new TestAuthentication("test2", false));
		getTokenServices().setSupportRefreshToken(true);
		getTokenServices().setReuseRefreshToken(false);
		OAuth2AccessToken accessToken = getTokenServices().createAccessToken(expectedAuthentication);
		OAuth2RefreshToken expectedExpiringRefreshToken = accessToken.getRefreshToken();
		OAuth2AccessToken refreshedAccessToken = getTokenServices().refreshAccessToken(
				expectedExpiringRefreshToken.getValue(), null);
		assertNotNull(refreshedAccessToken);
		assertEquals(1, getRefreshTokenCount());
	}

	protected abstract int getAccessTokenCount();

	protected abstract int getRefreshTokenCount();

	protected DefaultTokenServices getTokenServices() {
		return services;
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
