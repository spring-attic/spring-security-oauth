package org.springframework.security.oauth2.provider.token;

public class TestInMemoryOAuth2ProviderTokenServices extends TestRandomValueOAuth2ProviderTokenServicesBase {

  private InMemoryOAuth2ProviderTokenServices oauth2ProviderTokenServices;

  @Override
  protected void setUp() throws Exception {
    super.setUp();

    oauth2ProviderTokenServices = new InMemoryOAuth2ProviderTokenServices();
    oauth2ProviderTokenServices.afterPropertiesSet();
  }

  @Override
  RandomValueOAuth2ProviderTokenServices getRandomValueOAuth2ProviderTokenServices() {
    return oauth2ProviderTokenServices;
  }
}
