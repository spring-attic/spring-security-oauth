package org.springframework.security.oauth2.provider.token;

import org.junit.Before;

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

}
