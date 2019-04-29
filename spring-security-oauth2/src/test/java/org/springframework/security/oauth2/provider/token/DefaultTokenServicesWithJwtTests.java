package org.springframework.security.oauth2.provider.token;

import java.util.Collections;
import java.util.Map;

import org.junit.Test;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.oauth2.common.ExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.common.util.JsonParser;
import org.springframework.security.oauth2.common.util.JsonParserFactory;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

import static org.junit.Assert.*;

/**
 * @author Ryan Heaton
 * @author Dave Syer
 * 
 */
public class DefaultTokenServicesWithJwtTests extends AbstractDefaultTokenServicesTests {

	private JwtTokenStore tokenStore;
	JwtAccessTokenConverter enhancer = new JwtAccessTokenConverter();

	@Override
	protected TokenStore createTokenStore() {
		tokenStore = new JwtTokenStore(enhancer);
		return tokenStore;
	}

	@Override
	protected void configureTokenServices(DefaultTokenServices services) throws Exception {
		enhancer.afterPropertiesSet();
		services.setTokenEnhancer(enhancer);
		super.configureTokenServices(services);
	}

	@Test
	public void testRefreshedTokenHasIdThatMatchesAccessToken() throws Exception {
		JsonParser parser = JsonParserFactory.create();
		OAuth2Authentication authentication = createAuthentication();
		OAuth2AccessToken initialToken = getTokenServices().createAccessToken(
				authentication);
		ExpiringOAuth2RefreshToken expectedExpiringRefreshToken = (ExpiringOAuth2RefreshToken) initialToken
				.getRefreshToken();
		TokenRequest tokenRequest = new TokenRequest(Collections.singletonMap(
				"client_id", "id"), "id", null, null);
		OAuth2AccessToken refreshedAccessToken = getTokenServices().refreshAccessToken(
				expectedExpiringRefreshToken.getValue(), tokenRequest);
		Map<String, ?> accessTokenInfo = parser.parseMap(JwtHelper.decode(
				refreshedAccessToken.getValue()).getClaims());
		Map<String, ?> refreshTokenInfo = parser.parseMap(JwtHelper.decode(
				refreshedAccessToken.getRefreshToken().getValue()).getClaims());
		assertEquals("Access token ID does not match refresh token ATI",
				accessTokenInfo.get(AccessTokenConverter.JTI),
				refreshTokenInfo.get(AccessTokenConverter.ATI));
		assertNotSame("Refresh token re-used", expectedExpiringRefreshToken.getValue(),
				refreshedAccessToken.getRefreshToken().getValue());
	}

	@Test
	public void testReusedRefreshedTokenIsStored() throws Exception {

		InMemoryTokenStore tokenStore = new InMemoryTokenStore();

		getTokenServices().setSupportRefreshToken(true);
		getTokenServices().setReuseRefreshToken(true);
		getTokenServices().setTokenStore(tokenStore);

		OAuth2Authentication authentication = createAuthentication();

		OAuth2AccessToken initialToken = getTokenServices().createAccessToken(
				authentication);
		ExpiringOAuth2RefreshToken expectedExpiringRefreshToken = (ExpiringOAuth2RefreshToken) initialToken
				.getRefreshToken();

		OAuth2AccessToken testStoredAccessToken = tokenStore.readAccessToken(initialToken.getValue());
		assertNotNull("Access token was not stored", testStoredAccessToken);
		assertNotNull("Access token was not stored", testStoredAccessToken.getValue());

		OAuth2RefreshToken testStoredRefreshAccessToken = tokenStore.readRefreshToken(expectedExpiringRefreshToken.getValue());
		assertNotNull("Refresh token was not stored", testStoredRefreshAccessToken);
		assertNotNull("Refresh token was not stored", testStoredRefreshAccessToken.getValue());

		TokenRequest tokenRequest = new TokenRequest(Collections.singletonMap(
				"client_id", "id"), "id", null, null);

		OAuth2AccessToken refreshedAccessToken = getTokenServices().refreshAccessToken(
				expectedExpiringRefreshToken.getValue(), tokenRequest);
		ExpiringOAuth2RefreshToken refreshedExpectedExpiringRefreshToken = (ExpiringOAuth2RefreshToken) refreshedAccessToken
				.getRefreshToken();

		OAuth2AccessToken testStoredRefreshedAccessToken = tokenStore.readAccessToken(refreshedAccessToken.getValue());
		assertNotNull("Refreshed access token was not stored", testStoredRefreshedAccessToken);
		assertNotNull("Refreshed access token was not stored", testStoredRefreshedAccessToken.getValue());

		OAuth2RefreshToken testStoredRefreshedRefreshAccessToken = tokenStore.readRefreshToken(refreshedExpectedExpiringRefreshToken.getValue());
		assertNotNull("Refreshed refresh token was not stored", testStoredRefreshedRefreshAccessToken);
		assertNotNull("Refreshed refresh token was not stored", testStoredRefreshedRefreshAccessToken.getValue());
	}

	@Test
	public void testDoubleRefresh() throws Exception {
		JsonParser parser = JsonParserFactory.create();
		OAuth2Authentication authentication = createAuthentication();
		OAuth2AccessToken initialToken = getTokenServices().createAccessToken(
				authentication);
		TokenRequest tokenRequest = new TokenRequest(Collections.singletonMap(
				"client_id", "id"), "id", null, null);
		OAuth2AccessToken refreshedAccessToken = getTokenServices().refreshAccessToken(
				initialToken.getRefreshToken().getValue(), tokenRequest);
		refreshedAccessToken = getTokenServices().refreshAccessToken(
				refreshedAccessToken.getRefreshToken().getValue(), tokenRequest);
		Map<String, ?> accessTokenInfo = parser.parseMap(JwtHelper.decode(
				refreshedAccessToken.getValue()).getClaims());
		Map<String, ?> refreshTokenInfo = parser.parseMap(JwtHelper.decode(
				refreshedAccessToken.getRefreshToken().getValue()).getClaims());
		assertEquals("Access token ID does not match refresh token ATI",
				accessTokenInfo.get(AccessTokenConverter.JTI),
				refreshTokenInfo.get(AccessTokenConverter.ATI));
	}

}
