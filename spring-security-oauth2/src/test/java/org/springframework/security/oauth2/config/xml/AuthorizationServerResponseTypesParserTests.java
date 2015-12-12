package org.springframework.security.oauth2.config.xml;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.support.GenericXmlApplicationContext;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.response.CompositeResponseTypesHandler;
import org.springframework.security.oauth2.provider.response.ResponseTypesHandler;
import org.springframework.web.servlet.ModelAndView;

import java.util.Collections;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class AuthorizationServerResponseTypesParserTests {

	private static String RESOURCE_NAME = "authorization-server-response-types-handler.xml";

	private ConfigurableApplicationContext context;

	@Rule
	public ExpectedException expected = ExpectedException.none();

	public AuthorizationServerResponseTypesParserTests() {
		context = new GenericXmlApplicationContext(getClass(), RESOURCE_NAME);
	}
	
	@Test
	public void testCompositeResponseTypeHandlerRegistered() {
		CompositeResponseTypesHandler responseTypesHandler =
				context.getBean(CompositeResponseTypesHandler.class);
		Set<String> responseTypes = Collections.<String>singleton("any");
		assertTrue(responseTypesHandler.canHandleResponseTypes(responseTypes));
		ModelAndView modelAndView =
				responseTypesHandler.handleApprovedAuthorizationRequest(responseTypes, new AuthorizationRequest(), null, null);
		assertEquals("custom", modelAndView.getViewName());
	}
	
	public static class SimpleResponseTypesHandler implements ResponseTypesHandler {

		public boolean canHandleResponseTypes(Set<String> responseTypes) {
			return true;
		}
		public ModelAndView handleApprovedAuthorizationRequest(Set<String> responseTypes,
															   AuthorizationRequest authorizationRequest,
															   Authentication authentication,
															   AuthorizationCodeServices authorizationCodeServices) {
			return new ModelAndView("custom");
		}
	}

}
