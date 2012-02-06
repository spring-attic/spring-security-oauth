package org.springframework.security.oauth2.provider.token;

import static org.junit.Assert.assertEquals;

import java.util.Date;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

/**
 * @author Dave Syer
 * 
 */
public class TestInMemoryTokenStore extends TestTokenStoreBase {

	private InMemoryTokenStore tokenStore;

	@Override
	public InMemoryTokenStore getTokenStore() {
		return tokenStore;
	}

	@Before
	public void createStore() {
		tokenStore = new InMemoryTokenStore();
	}

	@Test
	public void testGetAccessTokenForDeletedUser() throws Exception {
		OAuth2Authentication expectedAuthentication = new OAuth2Authentication(new AuthorizationRequest("id", null,
				null, null), new TestAuthentication("test", false));
		OAuth2AccessToken expectedOAuth2AccessToken = new OAuth2AccessToken("testToken");
		getTokenStore().storeAccessToken(expectedOAuth2AccessToken, expectedAuthentication);
		assertEquals(expectedOAuth2AccessToken, getTokenStore().getAccessToken(expectedAuthentication));
		assertEquals(expectedAuthentication, getTokenStore().readAuthentication(expectedOAuth2AccessToken));
		OAuth2Authentication anotherAuthentication = new OAuth2Authentication(new AuthorizationRequest("id", null,
				null, null), new TestAuthentication("test", true));
		assertEquals(expectedOAuth2AccessToken, getTokenStore().getAccessToken(anotherAuthentication));
		// The generated key for the authentication is the same as before, but the two auths are not equal. This could
		// happen if there are 2 users in a system with the same username, or (more likely), if a user account was
		// deleted and re-created.
		assertEquals(anotherAuthentication, getTokenStore().readAuthentication(expectedOAuth2AccessToken));
	}

	@Test
	public void testTokenCountConsistency() throws Exception {
		for (int i = 0; i <= 10; i++) {
			OAuth2Authentication expectedAuthentication = new OAuth2Authentication(new AuthorizationRequest("id" + i,
					null, null, null), new TestAuthentication("test", false));
			OAuth2AccessToken expectedOAuth2AccessToken = new OAuth2AccessToken("testToken" + i);
			expectedOAuth2AccessToken.setExpiration(new Date(System.currentTimeMillis() - 1000));
			if (i > 1) {
				assertEquals(i, getTokenStore().getAccessTokenCount());
			}
			getTokenStore().storeAccessToken(expectedOAuth2AccessToken, expectedAuthentication);
		}
	}

	@Test
	public void testAutoFlush() throws Exception {
		getTokenStore().setFlushInterval(3);
		for (int i = 0; i <= 10; i++) {
			OAuth2Authentication expectedAuthentication = new OAuth2Authentication(new AuthorizationRequest("id" + i,
					null, null, null), new TestAuthentication("test", false));
			OAuth2AccessToken expectedOAuth2AccessToken = new OAuth2AccessToken("testToken" + i);
			expectedOAuth2AccessToken.setExpiration(new Date(System.currentTimeMillis() - 1000));
			if (i > 2) {
				assertEquals((i % 3 + 1), getTokenStore().getAccessTokenCount());
			}
			getTokenStore().storeAccessToken(expectedOAuth2AccessToken, expectedAuthentication);
		}
	}

}
