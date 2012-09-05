package org.springframework.security.oauth2.provider.token;

import junit.framework.TestCase;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.http.HttpMethod;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.web.client.RestTemplate;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Vidya Valmikinathan
 */
public class TestRemoteTokenServices extends TestCase {

    RemoteTokenServices tokenServices;
    RestTemplate restTemplate = Mockito.mock(RestTemplate.class);

    public void setUp(Map<String, Object> token) {
        tokenServices = Mockito.spy(new RemoteTokenServices());
        tokenServices.setClientId("client1");
        tokenServices.setClientSecret("secret");

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

        OAuth2Authentication authentication = tokenServices.loadAuthentication("token");
        assertNotNull(authentication);
        assertEquals(authentication.getPrincipal().toString(), "user1");
        assertTrue(authentication.isAuthenticated());
        assertFalse(authentication.isClientOnly());
        assertEquals(authentication.getAuthorizationRequest().getClientId(), "client1");
        assertTrue(authentication.getAuthorizationRequest().getResourceIds().contains("uaa"));
        assertTrue(authentication.getAuthorizationRequest().getScope().contains("uaa.user"));
    }

    @Test
    public void testLoadAuthenticationWithIncompleteToken() {
        Map<String, Object> validToken = new HashMap<String, Object>();
        validToken.put("client_id", "client1");
        validToken.put("scope", Arrays.asList("openid"));
        validToken.put("user_name", "user1");

        setUp(validToken);
        try {
            tokenServices.loadAuthentication("token");
            fail("Should have thrown IllegalStateException");
        } catch (IllegalStateException ex) { }
    }

    @Test
    public void testLoadAuthenticationWithErrorToken() {
        Map<String, Object> validToken = new HashMap<String, Object>();
        validToken.put("error", "expired token");

        setUp(validToken);
        try {
            tokenServices.loadAuthentication("token");
            fail("Should have thrown InvalidTokenException");
        } catch (InvalidTokenException ex) { }
    }

    @Test
    public void testReadAccessToken() {
        setUp(new HashMap<String, Object>());
        try {
            tokenServices.readAccessToken("token");
            fail("Should have thrown UnsupportedOperationException");
        } catch (UnsupportedOperationException ex) { }
    }
}
