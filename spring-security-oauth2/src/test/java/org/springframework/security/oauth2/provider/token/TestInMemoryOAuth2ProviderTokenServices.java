package org.springframework.security.oauth2.provider.token;

import org.junit.Before;

public class TestInMemoryOAuth2ProviderTokenServices extends TestRandomValueOAuth2ProviderTokenServicesBase {

  private InMemoryOAuth2ProviderTokenServices oauth2ProviderTokenServices;

  @Before
  public void setUp() throws Exception {
    oauth2ProviderTokenServices = new InMemoryOAuth2ProviderTokenServices();
    oauth2ProviderTokenServices.afterPropertiesSet();
  }

  @Override
  RandomValueOAuth2ProviderTokenServices getRandomValueOAuth2ProviderTokenServices() {
    return oauth2ProviderTokenServices;
  }
}
