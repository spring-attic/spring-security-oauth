package org.springframework.security.oauth2.config.xml;

import static org.junit.Assert.assertNotNull;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.support.GenericXmlApplicationContext;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.TokenRequest;

public class AuthorizationServerCustomGrantParserTests {
	
	private static String RESOURCE_NAME = "authorization-server-custom-grant.xml";
	
	private ConfigurableApplicationContext context;
	
	@Rule
	public ExpectedException expected = ExpectedException.none();
	
	public AuthorizationServerCustomGrantParserTests() {
		context = new GenericXmlApplicationContext(getClass(), RESOURCE_NAME);
	}
	
	@Test
	public void testCustomGrantRegistered() {
		TokenGranter granter = context.getBean(CompositeTokenGranter.class);
		assertNotNull("Custom grant registration failed!", granter.grant("test-grant", null));
	}
	
	public static class CustomTestTokenGranter implements TokenGranter {
		
		public CustomTestTokenGranter() {}

		public OAuth2AccessToken grant(String grantType,
				TokenRequest tokenRequest) {
			if (grantType.equals("test-grant")) {
				return new DefaultOAuth2AccessToken("test");
			}
			return null;
		}
		
	}

}
