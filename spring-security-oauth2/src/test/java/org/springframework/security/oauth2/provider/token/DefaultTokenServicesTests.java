package org.springframework.security.oauth2.provider.token;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.DefaultOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationManager;

public class DefaultTokenServicesTests {

	private DefaultTokenServices services;
	private TokenStore tokenStore = Mockito.mock(TokenStore.class);

	@Before
	public void init() throws Exception {
		services = new DefaultTokenServices();
		services.setTokenStore(tokenStore);
		services.afterPropertiesSet();
	}

	@Test(expected = InvalidTokenException.class)
	public void testAccidentalNullAuthentication() {
		Mockito.when(tokenStore.readAccessToken(Mockito.anyString())).thenReturn(
				new DefaultOAuth2AccessToken("FOO"));
		// A bug in the TokenStore or a race condition could lead to the authentication
		// being null even if the token is not:
		Mockito.when(tokenStore.readAuthentication(Mockito.any(OAuth2AccessToken.class)))
				.thenReturn(null);
		services.loadAuthentication("FOO");
	}

	@Test(expected = InvalidGrantException.class)
	public void testAuthenticationNofFound() {
		//given
		Mockito.when(tokenStore.readAuthenticationForRefreshToken(Mockito.any(DefaultOAuth2RefreshToken.class)))
				.thenReturn(null);

		Mockito.when(tokenStore.readRefreshToken(Mockito.anyString())).thenReturn(new DefaultOAuth2RefreshToken("FOO"));

		//when
		services.setSupportRefreshToken(true);
		services.setAuthenticationManager(new OAuth2AuthenticationManager());
		services.refreshAccessToken("1234132ed13432f3", null);
	}
}
