package org.springframework.security.oauth2.provider.token;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.io.Serializable;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;

import org.junit.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.common.ExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.ClientAuthenticationToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.code.UnconfirmedAuthorizationCodeAuthenticationToken;

public abstract class TestRandomValueOAuth2ProviderTokenServicesBase {

	abstract RandomValueOAuth2ProviderTokenServices getRandomValueOAuth2ProviderTokenServices();

	@Test
	public void testReadingAuthenticationForTokenThatDoesNotExist() {
		OAuth2AccessToken tok = new OAuth2AccessToken();
		tok.setValue("tokenThatDoesNotExist");
		assertNull(getRandomValueOAuth2ProviderTokenServices().readAuthentication(tok));
	}

	@Test
	public void testReadingAuthenticationForRefreshTokenThatDoesNotExist() {
		ExpiringOAuth2RefreshToken tok = new ExpiringOAuth2RefreshToken();
		tok.setValue("tokenThatDoesNotExist");
		assertNull(getRandomValueOAuth2ProviderTokenServices().readAuthentication(tok));
	}

	@Test
	public void testStoreAccessToken() {
		OAuth2Authentication<ClientAuthenticationToken> expectedAuthentication = new OAuth2Authentication<ClientAuthenticationToken>(
				new UnconfirmedAuthorizationCodeAuthenticationToken("id", null, null, null), new TestAuthentication(
						"test2", false));
		OAuth2AccessToken expectedOAuth2AccessToken = new OAuth2AccessToken();
		expectedOAuth2AccessToken.setValue("testToken");
		getRandomValueOAuth2ProviderTokenServices().storeAccessToken(expectedOAuth2AccessToken, expectedAuthentication);

		OAuth2AccessToken actualOAuth2AccessToken = getRandomValueOAuth2ProviderTokenServices().readAccessToken(
				"testToken");
		assertEquals(expectedOAuth2AccessToken, actualOAuth2AccessToken);
		assertEquals(expectedAuthentication,
				getRandomValueOAuth2ProviderTokenServices().readAuthentication(expectedOAuth2AccessToken));
		getRandomValueOAuth2ProviderTokenServices().removeAccessToken("testToken");
		assertNull(getRandomValueOAuth2ProviderTokenServices().readAccessToken("testToken"));
		assertNull(getRandomValueOAuth2ProviderTokenServices().readAuthentication(expectedOAuth2AccessToken));
	}

	@Test
	public void testReadingAccessTokenForTokenThatDoesNotExist() {
		assertNull(getRandomValueOAuth2ProviderTokenServices().readAccessToken("tokenThatDoesNotExist"));
	}

	@Test
	public void testStoreRefreshToken() {
		ExpiringOAuth2RefreshToken expectedExpiringRefreshToken = new ExpiringOAuth2RefreshToken();
		OAuth2Authentication<ClientAuthenticationToken> expectedAuthentication = new OAuth2Authentication<ClientAuthenticationToken>(
				new UnconfirmedAuthorizationCodeAuthenticationToken("id", null, null, null), new TestAuthentication(
						"test2", false));
		expectedExpiringRefreshToken.setValue("testToken");
		getRandomValueOAuth2ProviderTokenServices().storeRefreshToken(expectedExpiringRefreshToken,
				expectedAuthentication);

		ExpiringOAuth2RefreshToken actualExpiringRefreshToken = getRandomValueOAuth2ProviderTokenServices()
				.readRefreshToken("testToken");
		assertEquals(expectedExpiringRefreshToken, actualExpiringRefreshToken);
		assertEquals(expectedAuthentication,
				getRandomValueOAuth2ProviderTokenServices().readAuthentication(expectedExpiringRefreshToken));
		getRandomValueOAuth2ProviderTokenServices().removeRefreshToken("testToken");
		assertNull(getRandomValueOAuth2ProviderTokenServices().readRefreshToken("testToken"));
		assertNull(getRandomValueOAuth2ProviderTokenServices().readAuthentication(expectedExpiringRefreshToken));
	}

	@Test
	public void testReadingRefreshTokenForTokenThatDoesNotExist() {
		getRandomValueOAuth2ProviderTokenServices().readRefreshToken("tokenThatDoesNotExist");
	}

	@Test
	public void testRefreshedTokenHasScopes() {
		getRandomValueOAuth2ProviderTokenServices().setSupportRefreshToken(true);
		ExpiringOAuth2RefreshToken expectedExpiringRefreshToken = new ExpiringOAuth2RefreshToken();
		expectedExpiringRefreshToken.setExpiration(new Date(System.currentTimeMillis() + 100000));
		OAuth2Authentication<ClientAuthenticationToken> expectedAuthentication = new OAuth2Authentication<ClientAuthenticationToken>(
				new UnconfirmedAuthorizationCodeAuthenticationToken("id", Collections.singleton("read"), null, null),
				new TestAuthentication("test2", false));
		expectedExpiringRefreshToken.setValue("testToken");
		getRandomValueOAuth2ProviderTokenServices().storeRefreshToken(expectedExpiringRefreshToken,
				expectedAuthentication);
		OAuth2AccessToken refreshedAccessToken = getRandomValueOAuth2ProviderTokenServices().refreshAccessToken(
				expectedExpiringRefreshToken.getValue());
		assertEquals("[read]", refreshedAccessToken.getScope().toString());
	}

	protected static class TestAuthentication implements Authentication, Serializable {
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
