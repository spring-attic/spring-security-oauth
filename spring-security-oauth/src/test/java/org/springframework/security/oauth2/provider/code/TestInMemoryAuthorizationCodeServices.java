package org.springframework.security.oauth2.provider.code;

import org.junit.Before;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.InMemoryAuthorizationCodeServices;

public class TestInMemoryAuthorizationCodeServices extends TestAuthorizationCodeServicesBase {

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
