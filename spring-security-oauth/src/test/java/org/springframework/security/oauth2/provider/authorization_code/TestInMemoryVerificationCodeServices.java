package org.springframework.security.oauth2.provider.authorization_code;

import org.junit.Before;

public class TestInMemoryVerificationCodeServices extends TestVerificationCodeServicesBase {

	private InMemoryAuthorizationCodeServices verificationCodeServices;

	@Before
	public void setUp() throws Exception {
		verificationCodeServices = new InMemoryAuthorizationCodeServices();
		verificationCodeServices.afterPropertiesSet();
	}

	@Override
  AuthorizationCodeServices getVerificationCodeServices() {
		return verificationCodeServices;
	}
}
