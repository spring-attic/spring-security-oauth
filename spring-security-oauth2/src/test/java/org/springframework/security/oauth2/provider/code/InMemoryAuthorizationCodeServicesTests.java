package org.springframework.security.oauth2.provider.code;

import org.junit.jupiter.api.BeforeEach;

public class InMemoryAuthorizationCodeServicesTests extends AuthorizationCodeServicesBaseTests {

    private InMemoryAuthorizationCodeServices authorizationCodeServices;

    @BeforeEach
    void setUp() throws Exception {
        authorizationCodeServices = new InMemoryAuthorizationCodeServices();
    }

    @Override
    AuthorizationCodeServices getAuthorizationCodeServices() {
        return authorizationCodeServices;
    }
}
