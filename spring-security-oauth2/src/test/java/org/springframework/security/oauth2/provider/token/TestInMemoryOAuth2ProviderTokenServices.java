package org.springframework.security.oauth2.provider.token;

import org.junit.Before;

public class TestInMemoryOAuth2ProviderTokenServices extends TestRandomValueOAuth2ProviderTokenServicesBase {
  private TokenStore tokenStore;

  @Before
  public void createStore() {
    tokenStore = new InMemoryTokenStore();
  }

  @Override
  TokenStore getTokenStore() {
    return tokenStore;
  }
}
