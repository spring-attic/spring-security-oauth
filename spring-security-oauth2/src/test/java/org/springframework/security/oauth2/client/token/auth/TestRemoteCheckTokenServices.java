package org.springframework.security.oauth2.client.token.auth;

import junit.framework.TestCase;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.web.client.RestTemplate;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class TestRemoteCheckTokenServices extends TestCase {
    RemoteCheckTokenServices tokenServices;
    RestTemplate restTemplate = Mockito.mock(RestTemplate.class);

    public void setUp(Map<String, Object> token) {
        tokenServices = Mockito.spy(new RemoteCheckTokenServices("client1", "secret", "someurl"));

        Mockito.doReturn(token).when(tokenServices).validateToken("token");
    }

    @Test
    public void testLoadAuthenticationWithValidToken() {
        Map<String, Object> validToken = new HashMap<String, Object>();
        validToken.put("client_id", "client1");
        validToken.put("aud", Arrays.asList("uaa", "openid"));
        validToken.put("scope", Arrays.asList("uaa.user", "openid"));
        validToken.put("user_name", "user1");

        setUp(validToken);

        Authentication authentication = tokenServices.loadAuthentication(new DefaultOAuth2AccessToken("token"));
        assertNotNull(authentication);
        assertEquals(authentication.getPrincipal().toString(), "user1");
        assertTrue(authentication.isAuthenticated());

        assertTrue(authentication instanceof OAuth2Authentication);
        OAuth2Authentication oauth2Authentication = (OAuth2Authentication) authentication;
        assertFalse(oauth2Authentication.isClientOnly());
        assertEquals(oauth2Authentication.getAuthorizationRequest().getClientId(), "client1");
        assertTrue(oauth2Authentication.getAuthorizationRequest().getResourceIds().contains("uaa"));
        assertTrue(oauth2Authentication.getAuthorizationRequest().getScope().contains("uaa.user"));
    }

    @Test
    public void testLoadAuthenticationWithIncompleteToken() {
        Map<String, Object> validToken = new HashMap<String, Object>();
        validToken.put("client_id", "client1");
        validToken.put("scope", Arrays.asList("openid"));
        validToken.put("user_name", "user1");

        setUp(validToken);
        try {
            tokenServices.loadAuthentication(new DefaultOAuth2AccessToken("token"));
            fail("Should have thrown IllegalStateException");
        } catch (IllegalStateException ex) { }
    }

    @Test
    public void testLoadAuthenticationWithErrorToken() {
        Map<String, Object> validToken = new HashMap<String, Object>();
        validToken.put("error", "expired token");

        setUp(validToken);
        try {
            tokenServices.loadAuthentication(new DefaultOAuth2AccessToken("token"));
            fail("Should have thrown InvalidTokenException");
        } catch (InvalidTokenException ex) { }
    }
}
