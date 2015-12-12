package org.springframework.security.oauth2.config.xml;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.support.GenericXmlApplicationContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationProcessingFilter;
import org.springframework.security.oauth2.provider.endpoint.AuthorizationEndpoint;
import org.springframework.security.oauth2.provider.response.AuthorizationRequestViewResolver;
import org.springframework.security.oauth2.provider.response.ResponseTypesHandler;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.servlet.View;
import org.springframework.web.servlet.view.RedirectView;

import static org.junit.Assert.assertEquals;

public class AuthorizationServerAuthorizationRequestViewResolverParserTests {

    private static String RESOURCE_NAME = "authorization-server-authorization-request-view-resolver.xml";

    private ConfigurableApplicationContext context;

    @Rule
    public ExpectedException expected = ExpectedException.none();

    public AuthorizationServerAuthorizationRequestViewResolverParserTests() {
        context = new GenericXmlApplicationContext(getClass(), RESOURCE_NAME);
    }

    @Test
    public void testCompositeResponseTypeHandlerRegistered() {
        AuthorizationRequestViewResolver requestViewResolver =
                context.getBean(AuthorizationRequestViewResolver.class);
        assertEquals("successfulAuthorizationCodeView", ((RedirectView)requestViewResolver.getSuccessfulAuthorizationCodeView(null, null)).getUrl());

        AuthorizationEndpoint authorizationEndpoint = context.getBean(AuthorizationEndpoint.class);
        assertEquals(requestViewResolver, ReflectionTestUtils.getField(authorizationEndpoint, "authorizationRequestViewResolver"));

        ResponseTypesHandler responseTypesHandler = context.getBean(ResponseTypesHandler.class);
        assertEquals(requestViewResolver, ReflectionTestUtils.getField(responseTypesHandler, "authorizationRequestViewResolver"));
    }

    public static class SimpleAuthorizationRequestViewResolver implements AuthorizationRequestViewResolver {
        public View getSuccessfulAuthorizationCodeView(AuthorizationRequest authorizationRequest, String authorizationCode) {
            return new RedirectView("successfulAuthorizationCodeView");
        }

        public View getSuccessfulImplicitGrantView(AuthorizationRequest authorizationRequest, OAuth2AccessToken accessToken) {
            return null;
        }

        public View getUnsuccessfulView(AuthorizationRequest authorizationRequest, OAuth2Exception failure) {
            return null;
        }
    }

}
