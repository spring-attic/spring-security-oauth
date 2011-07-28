package org.springframework.security.oauth2.provider.verification;

import org.junit.Before;

public class TestInMemoryVerificationCodeServices extends TestVerificationCodeServicesBase {

	private InMemoryVerificationCodeServices verificationCodeServices;

	@Before
	public void setUp() throws Exception {
		verificationCodeServices = new InMemoryVerificationCodeServices();
		verificationCodeServices.afterPropertiesSet();
	}

	@Override
	VerificationCodeServices getVerificationCodeServices() {
		return verificationCodeServices;
	}
}
