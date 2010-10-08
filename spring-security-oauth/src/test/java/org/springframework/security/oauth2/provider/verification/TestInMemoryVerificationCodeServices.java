package org.springframework.security.oauth2.provider.verification;

public class TestInMemoryVerificationCodeServices extends TestVerificationCodeServicesBase {

  private InMemoryVerificationCodeServices verificationCodeServices;

  @Override
  protected void setUp() throws Exception {
    super.setUp();

    verificationCodeServices = new InMemoryVerificationCodeServices();
    verificationCodeServices.afterPropertiesSet();
  }

  @Override
  VerificationCodeServices getVerificationCodeServices() {
    return verificationCodeServices;
  }
}
