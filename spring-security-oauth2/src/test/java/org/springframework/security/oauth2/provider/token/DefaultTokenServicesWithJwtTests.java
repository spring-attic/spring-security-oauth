package org.springframework.security.oauth2.provider.token;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotSame;

import java.util.Collections;
import java.util.Map;

import org.junit.Test;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.oauth2.common.ExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.util.JsonParser;
import org.springframework.security.oauth2.common.util.JsonParserFactory;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

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
