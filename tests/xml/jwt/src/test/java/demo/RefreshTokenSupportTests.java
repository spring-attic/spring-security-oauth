package demo;

import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

import sparklr.common.AbstractRefreshTokenSupportTests;

/**
 * @author Ryan Heaton
 * @author Dave Syer
 */
@SpringApplicationConfiguration(classes=Application.class)
public class RefreshTokenSupportTests extends AbstractRefreshTokenSupportTests {

	protected void verifyAccessTokens(OAuth2AccessToken oldAccessToken, OAuth2AccessToken newAccessToken) {
		// make sure the new access token can be used.
		verifyTokenResponse(newAccessToken.getValue(), HttpStatus.OK);
		// the old access token is still valid because there is no state on the server.
		verifyTokenResponse(oldAccessToken.getValue(), HttpStatus.OK);
	}

}
