package org.springframework.security.oauth2.provider.token;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import java.util.Collections;
import java.util.Date;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
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
public class TestDefaultTokenServicesWithInMemory extends AbstractTestDefaultTokenServices {

	private InMemoryTokenStore tokenStore;
	
	@Rule
	public ExpectedException expected = ExpectedException.none();

	@Test
	public void testExpiredToken() throws Exception {
		OAuth2Authentication expectedAuthentication = new OAuth2Authentication(new AuthorizationRequest("id",
				Collections.singleton("read"), null, null), new TestAuthentication("test2", false));
		DefaultOAuth2AccessToken firstAccessToken = (DefaultOAuth2AccessToken) getTokenServices()
				.createAccessToken(expectedAuthentication);
		// Make it expire (and rely on mutable state in volatile token store)
		firstAccessToken.setExpiration(new Date(System.currentTimeMillis() - 1000));
		expected.expect(InvalidTokenException.class);
		expected.expectMessage("expired");
		getTokenServices().loadAuthentication(firstAccessToken.getValue());
	}
	
	
	@Test
	public void testDifferentRefreshTokenMaintainsState() throws Exception {
		// create access token
		getTokenServices().setAccessTokenValiditySeconds(1);
		getTokenServices().setClientDetailsService(new ClientDetailsService() {
			public ClientDetails loadClientByClientId(String clientId) throws OAuth2Exception {
				BaseClientDetails client = new BaseClientDetails();
				client.setAccessTokenValiditySeconds(1);
				return client;
			}
		});
		OAuth2Authentication expectedAuthentication = new OAuth2Authentication(new AuthorizationRequest("id",
				Collections.singleton("read"), null, null), new TestAuthentication("test2", false));
		DefaultOAuth2AccessToken firstAccessToken = (DefaultOAuth2AccessToken) getTokenServices()
				.createAccessToken(expectedAuthentication);
		OAuth2RefreshToken expectedExpiringRefreshToken = firstAccessToken.getRefreshToken();
		// Make it expire (and rely on mutable state in volatile token store)
		firstAccessToken.setExpiration(new Date(System.currentTimeMillis() - 1000));
		// create another access token
		OAuth2AccessToken secondAccessToken = getTokenServices().createAccessToken(expectedAuthentication);
		assertFalse("The new access token should be different",
				firstAccessToken.getValue().equals(secondAccessToken.getValue()));
		assertEquals("The new access token should have the same refresh token",
				expectedExpiringRefreshToken.getValue(), secondAccessToken.getRefreshToken().getValue());
		// refresh access token with refresh token
		getTokenServices().refreshAccessToken(expectedExpiringRefreshToken.getValue(), expectedAuthentication
				.getAuthorizationRequest().getScope());
		assertEquals(1, getAccessTokenCount());
	}

	@Override
	protected TokenStore createTokenStore() {
		tokenStore = new InMemoryTokenStore();
		return tokenStore;
	}

	@Override
	protected int getAccessTokenCount() {
		return tokenStore.getAccessTokenCount();
	}

	@Override
	protected int getRefreshTokenCount() {
		return tokenStore.getRefreshTokenCount();
	}	

}
