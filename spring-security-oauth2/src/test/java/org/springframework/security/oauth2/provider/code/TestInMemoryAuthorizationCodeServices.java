package org.springframework.security.oauth2.provider.code;

import org.junit.Before;

public class TestInMemoryAuthorizationCodeServices extends TestAuthorizationCodeServicesBase {

	private InMemoryAuthorizationCodeServices authorizationCodeServices;

	@Before
	public void setUp() throws Exception {
		authorizationCodeServices = new InMemoryAuthorizationCodeServices();
	}

	@Override
	AuthorizationCodeServices getAuthorizationCodeServices() {
		return authorizationCodeServices;
	}
}
