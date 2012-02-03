package org.springframework.security.oauth2.provider.token;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.Serializable;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.common.ExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.BaseClientDetails;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

/**
 * @author Ryan Heaton
 * @author Dave Syer
 * 
 */
public class TestRandomValueTokenServices {

	private InMemoryTokenStore tokenStore;

	private RandomValueTokenServices services;

	@Before
	public void createStore() throws Exception {
		tokenStore = new InMemoryTokenStore();
		services = new RandomValueTokenServices();
		services.setTokenStore(tokenStore);
		services.afterPropertiesSet();
		services.setSupportRefreshToken(true);
	}

	@Test
	public void testRefreshedTokenHasScopes() throws Exception {
		ExpiringOAuth2RefreshToken expectedExpiringRefreshToken = new ExpiringOAuth2RefreshToken("testToken", new Date(
				System.currentTimeMillis() + 100000));
		OAuth2Authentication expectedAuthentication = new OAuth2Authentication(new AuthorizationRequest("id",
				Collections.singleton("read"), null, null), new TestAuthentication("test2", false));
		tokenStore.storeRefreshToken(expectedExpiringRefreshToken, expectedAuthentication);
		OAuth2AccessToken refreshedAccessToken = services.refreshAccessToken(expectedExpiringRefreshToken.getValue(),
				null);
		assertEquals("[read]", refreshedAccessToken.getScope().toString());
	}

	@Test
	public void testUnlimitedTokenExpiry() throws Exception {
		services.setAccessTokenValiditySeconds(0);
		OAuth2Authentication expectedAuthentication = new OAuth2Authentication(new AuthorizationRequest("id",
				Collections.singleton("read"), null, null), new TestAuthentication("test2", false));
		OAuth2AccessToken accessToken = services.createAccessToken(expectedAuthentication);
		assertEquals(0, accessToken.getExpiresIn());
		assertEquals(null, accessToken.getExpiration());
	}

	@Test
	public void testDefaultTokenExpiry() throws Exception {
		services.setAccessTokenValiditySeconds(100);
		OAuth2Authentication expectedAuthentication = new OAuth2Authentication(new AuthorizationRequest("id",
				Collections.singleton("read"), null, null), new TestAuthentication("test2", false));
		OAuth2AccessToken accessToken = services.createAccessToken(expectedAuthentication);
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
		OAuth2Authentication expectedAuthentication = new OAuth2Authentication(new AuthorizationRequest("id",
				Collections.singleton("read"), null, null), new TestAuthentication("test2", false));
		OAuth2AccessToken accessToken = services.createAccessToken(expectedAuthentication);
		assertTrue(100 >= accessToken.getExpiresIn());
	}

	@Test
	public void testOneAccessTokenPerAuthentication() throws Exception {
		OAuth2Authentication authentication = new OAuth2Authentication(new AuthorizationRequest("id",
				Collections.singleton("read"), null, null), new TestAuthentication("test2", false));
		OAuth2AccessToken first = services.createAccessToken(authentication);
		assertEquals(1, tokenStore.getAccessTokenCount());
		assertEquals(1, tokenStore.getRefreshTokenCount());
		OAuth2AccessToken second = services.createAccessToken(authentication);
		assertEquals(first, second);
		assertEquals(1, tokenStore.getAccessTokenCount());
		assertEquals(1, tokenStore.getRefreshTokenCount());
	}

	@Test
	public void testOneAccessTokenPerUniqueAuthentication() throws Exception {
		services.createAccessToken(new OAuth2Authentication(new AuthorizationRequest("id", Collections
				.singleton("read"), null, null), new TestAuthentication("test2", false)));
		assertEquals(1, tokenStore.getAccessTokenCount());
		services.createAccessToken(new OAuth2Authentication(new AuthorizationRequest("id", Collections
				.singleton("write"), null, null), new TestAuthentication("test2", false)));
		assertEquals(2, tokenStore.getAccessTokenCount());
	}

	private static class TestAuthentication implements Authentication, Serializable {
		private String name;

		private boolean authenticated;

		public TestAuthentication(String name, boolean authenticated) {
			this.name = name;
			this.authenticated = authenticated;
		}

		public Collection<GrantedAuthority> getAuthorities() {
			return null;
		}

		public Object getCredentials() {
			return null;
		}

		public Object getDetails() {
			return null;
		}

		public Object getPrincipal() {
			return null;
		}

		public boolean isAuthenticated() {
			return authenticated;
		}

		public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
			this.authenticated = isAuthenticated;
		}

		public String getName() {
			return name;
		}

		@Override
		public boolean equals(Object o) {
			if (this == o)
				return true;
			if (o == null || getClass() != o.getClass())
				return false;

			TestAuthentication that = (TestAuthentication) o;

			if (authenticated != that.authenticated)
				return false;
			if (name != null ? !name.equals(that.name) : that.name != null)
				return false;

			return true;
		}

		@Override
		public int hashCode() {
			int result = name != null ? name.hashCode() : 0;
			result = 31 * result + (authenticated ? 1 : 0);
			return result;
		}
	}
}
