package org.springframework.security.oauth2.config.xml;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.support.GenericXmlApplicationContext;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.response.CompositeCustomResponseTypesHandler;
import org.springframework.security.oauth2.provider.response.CustomResponseTypesHandler;
import org.springframework.web.servlet.ModelAndView;

import java.util.Collections;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class AuthorizationServerCustomResponseTypesParserTests {

	private static String RESOURCE_NAME = "authorization-server-custom-response-types-handler.xml";

	private ConfigurableApplicationContext context;

	@Rule
	public ExpectedException expected = ExpectedException.none();

	public AuthorizationServerCustomResponseTypesParserTests() {
		context = new GenericXmlApplicationContext(getClass(), RESOURCE_NAME);
	}
	
	@Test
	public void testCustomResponseTypeHandlerRegistered() {
		CompositeCustomResponseTypesHandler customResponseTypesHandler =
				context.getBean(CompositeCustomResponseTypesHandler.class);
		assertTrue(customResponseTypesHandler.canHandleResponseTypes(Collections.<String>emptySet()));
		ModelAndView modelAndView =
				customResponseTypesHandler.handleApprovedAuthorizationRequest(new AuthorizationRequest(), null);
		assertEquals("custom", modelAndView.getViewName());
	}
	
	public static class SimpleCustomResponseTypesHandler implements CustomResponseTypesHandler {

		public boolean canHandleResponseTypes(Set<String> responseTypes) {
			return true;
		}
		public ModelAndView handleApprovedAuthorizationRequest(AuthorizationRequest authorizationRequest, Authentication authentication) {
			return new ModelAndView("custom");
		}
	}

}
