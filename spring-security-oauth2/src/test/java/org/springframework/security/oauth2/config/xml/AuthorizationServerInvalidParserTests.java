package org.springframework.security.oauth2.config.xml;

import static org.junit.Assert.assertNotNull;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.beans.factory.parsing.BeanDefinitionParsingException;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.support.GenericXmlApplicationContext;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.TokenGranter;

public class AuthorizationServerInvalidParserTests {
	
	private static String RESOURCE_NAME = "authorization-server-invalid.xml";
	
	private ConfigurableApplicationContext context;
	
	@Rule
	public ExpectedException expected = ExpectedException.none();
	
	@Test
	public void testCustomGrantRegistered() {
		expected.expect(BeanDefinitionParsingException.class);
		expected.expectMessage("ClientDetailsService");
		context = new GenericXmlApplicationContext(getClass(), RESOURCE_NAME);
		TokenGranter granter = context.getBean(CompositeTokenGranter.class);
		assertNotNull(granter);
	}

}
