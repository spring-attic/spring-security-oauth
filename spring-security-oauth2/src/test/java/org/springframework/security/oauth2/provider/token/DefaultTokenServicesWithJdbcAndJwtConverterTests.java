package org.springframework.security.oauth2.provider.token;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.Collections;

import org.junit.After;
import org.junit.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.security.oauth2.common.ExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtJdbcTokenConverter;

/**
 * @author Dave Syer
 * 
 */
public class DefaultTokenServicesWithJdbcAndJwtConverterTests extends AbstractDefaultTokenServicesTests {

	private EmbeddedDatabase db;

	private JwtJdbcTokenConverter enhancer = new JwtJdbcTokenConverter();

	@Test
	public void testRefreshedTokenIsReused() throws Exception {
		OAuth2Authentication authentication = createAuthentication();
		getTokenServices().setSupportRefreshToken(true);
		getTokenServices().setReuseRefreshToken(true);
		OAuth2AccessToken accessToken = getTokenServices().createAccessToken(authentication);
		TokenRequest tokenRequest = new TokenRequest(Collections.singletonMap("client_id", "id"), "id", null, null);
		OAuth2AccessToken refreshedAccessToken = getTokenServices().refreshAccessToken(accessToken.getRefreshToken().getValue(), tokenRequest);
		assertTrue(accessToken.getRefreshToken().equals(refreshedAccessToken.getRefreshToken()));
		OAuth2AccessToken result = getTokenStore().getAccessToken(authentication);
		assertEquals(refreshedAccessToken, result);
		assertEquals(refreshedAccessToken.getRefreshToken(), result.getRefreshToken());
		assertEquals(refreshedAccessToken.getRefreshToken(), getTokenStore().readRefreshToken(accessToken.getRefreshToken().getValue()));
	}

	@Test
	public void testAccessTokenRefreshTokenMissing() throws Exception {
		OAuth2Authentication authentication = createAuthentication();
		getTokenServices().setSupportRefreshToken(true);
		getTokenServices().setReuseRefreshToken(true);
		OAuth2AccessToken accessToken = getTokenServices().createAccessToken(authentication);
		getTokenStore().removeRefreshToken(accessToken.getRefreshToken());
		
		accessToken = getTokenServices().createAccessToken(authentication);
		TokenRequest tokenRequest = new TokenRequest(Collections.singletonMap("client_id", "id"), "id", null, null);
		OAuth2AccessToken refreshedAccessToken = getTokenServices().refreshAccessToken(accessToken.getRefreshToken().getValue(), tokenRequest);
		
		assertTrue(accessToken.getRefreshToken().equals(refreshedAccessToken.getRefreshToken()));
		OAuth2AccessToken result = getTokenStore().getAccessToken(authentication);
		assertEquals(refreshedAccessToken, result);
		assertEquals(refreshedAccessToken.getRefreshToken(), result.getRefreshToken());
		assertEquals(refreshedAccessToken.getRefreshToken(), getTokenStore().readRefreshToken(accessToken.getRefreshToken().getValue()));
	}
	
	@Override
	protected void configureTokenServices(DefaultTokenServices services) throws Exception {
		enhancer.afterPropertiesSet();
		services.setTokenEnhancer(enhancer);
		super.configureTokenServices(services);
	}

	protected TokenStore createTokenStore() {
		db = new EmbeddedDatabaseBuilder().addDefaultScripts().build();
		return new JdbcTokenStore(db);
	}

	@After
	public void tearDown() throws Exception {
		db.shutdown();
	}

	protected int getAccessTokenCount() {
		return new JdbcTemplate(db).queryForObject("SELECT COUNT(*) FROM OAUTH_ACCESS_TOKEN", Integer.class);
	}

	protected int getRefreshTokenCount() {
		return new JdbcTemplate(db).queryForObject("SELECT COUNT(*) FROM OAUTH_REFRESH_TOKEN", Integer.class);
	}

	protected TokenEnhancer createTokenEnhancer1Tester(ExpiringOAuth2RefreshToken refreshToken) {
		return enhancer;
	}

	protected TokenEnhancer createTokenEnhancer2Tester() {
		return enhancer;
	}

}
