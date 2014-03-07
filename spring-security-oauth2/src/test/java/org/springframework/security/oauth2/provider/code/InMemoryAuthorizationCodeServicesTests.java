package org.springframework.security.oauth2.provider.code;

import org.junit.Before;

public class InMemoryAuthorizationCodeServicesTests extends AuthorizationCodeServicesBaseTests {

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
