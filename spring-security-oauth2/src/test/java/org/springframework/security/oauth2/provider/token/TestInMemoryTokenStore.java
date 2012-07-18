package org.springframework.security.oauth2.provider.token;

import static org.junit.Assert.assertEquals;

import java.util.Date;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.provider.DefaultAuthorizationRequest;
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
	public void testTokenCountConsistency() throws Exception {
		for (int i = 0; i <= 10; i++) {
			OAuth2Authentication expectedAuthentication = new OAuth2Authentication(new DefaultAuthorizationRequest("id" + i,
					null), new TestAuthentication("test", false));
			DefaultOAuth2AccessToken expectedOAuth2AccessToken = new DefaultOAuth2AccessToken("testToken" + i);
			expectedOAuth2AccessToken.setExpiration(new Date(System.currentTimeMillis() - 1000));
			if (i > 1) {
				assertEquals(i, getTokenStore().getAccessTokenCount());
			}
			getTokenStore().storeAccessToken(expectedOAuth2AccessToken, expectedAuthentication);
		}
	}

	@Test
	public void testTokenCountConsistentWithExpiryQueue() throws Exception {
		OAuth2Authentication expectedAuthentication = new OAuth2Authentication(new DefaultAuthorizationRequest("id", null), new TestAuthentication("test", false));
		DefaultOAuth2AccessToken expectedOAuth2AccessToken = new DefaultOAuth2AccessToken("testToken");
		expectedOAuth2AccessToken.setExpiration(new Date(System.currentTimeMillis()+10000));
		for (int i = 0; i <= 10; i++) {
			getTokenStore().storeAccessToken(expectedOAuth2AccessToken, expectedAuthentication);
			assertEquals(getTokenStore().getAccessTokenCount(), getTokenStore().getExpiryTokenCount());
		}
	}

	@Test
	public void testAutoFlush() throws Exception {
		getTokenStore().setFlushInterval(3);
		for (int i = 0; i <= 10; i++) {
			OAuth2Authentication expectedAuthentication = new OAuth2Authentication(new DefaultAuthorizationRequest("id" + i,
					null), new TestAuthentication("test", false));
			DefaultOAuth2AccessToken expectedOAuth2AccessToken = new DefaultOAuth2AccessToken("testToken" + i);
			expectedOAuth2AccessToken.setExpiration(new Date(System.currentTimeMillis() - 1000));
			if (i > 2) {
				assertEquals((i % 3 + 1), getTokenStore().getAccessTokenCount());
			}
			getTokenStore().storeAccessToken(expectedOAuth2AccessToken, expectedAuthentication);
		}
	}
}
