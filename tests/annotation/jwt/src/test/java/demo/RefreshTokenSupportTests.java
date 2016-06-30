package demo;

import static org.junit.Assert.assertEquals;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.test.util.ReflectionTestUtils;

import sparklr.common.AbstractRefreshTokenSupportTests;

/**
 * @author Ryan Heaton
 * @author Dave Syer
 */
@SpringApplicationConfiguration(classes=Application.class)
public class RefreshTokenSupportTests extends AbstractRefreshTokenSupportTests {
	
	@Autowired
	@Qualifier("defaultAuthorizationServerTokenServices")
	private DefaultTokenServices services;

	protected void verifyAccessTokens(OAuth2AccessToken oldAccessToken, OAuth2AccessToken newAccessToken) {
		// make sure the new access token can be used.
		verifyTokenResponse(newAccessToken.getValue(), HttpStatus.OK);
		// the old access token is still valid because there is no state on the server.
		verifyTokenResponse(oldAccessToken.getValue(), HttpStatus.OK);
		JwtTokenStore store = (JwtTokenStore) ReflectionTestUtils.getField(services, "tokenStore");
		OAuth2AccessToken token = store.readAccessToken(oldAccessToken.getValue());
		OAuth2AccessToken refresh = ReflectionTestUtils.invokeMethod(store, "convertAccessToken", oldAccessToken.getRefreshToken().getValue());
		assertEquals(refresh.getExpiration().getTime(), token.getExpiration().getTime() + 100000);
	}
	
}
