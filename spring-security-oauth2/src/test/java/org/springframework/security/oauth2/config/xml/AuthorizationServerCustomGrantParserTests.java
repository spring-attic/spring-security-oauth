package org.springframework.security.oauth2.config.xml;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import org.junit.Rule;
import org.junit.jupiter.api.Test;
import org.junit.rules.ExpectedException;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.support.GenericXmlApplicationContext;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.TokenRequest;

class AuthorizationServerCustomGrantParserTests {

    private static String RESOURCE_NAME = "authorization-server-custom-grant.xml";

    private ConfigurableApplicationContext context;

    @Rule
    public ExpectedException expected = ExpectedException.none();

    public AuthorizationServerCustomGrantParserTests() {
        context = new GenericXmlApplicationContext(getClass(), RESOURCE_NAME);
    }

    @Test
    void testCustomGrantRegistered() {
        TokenGranter granter = context.getBean(CompositeTokenGranter.class);
        assertNotNull(granter.grant("test-grant", null), "Custom grant registration failed!");
    }

    public static class CustomTestTokenGranter implements TokenGranter {

        public CustomTestTokenGranter() {
        }

        public OAuth2AccessToken grant(String grantType, TokenRequest tokenRequest) {
            if (grantType.equals("test-grant")) {
                return new DefaultOAuth2AccessToken("test");
            }
            return null;
        }
    }
}
