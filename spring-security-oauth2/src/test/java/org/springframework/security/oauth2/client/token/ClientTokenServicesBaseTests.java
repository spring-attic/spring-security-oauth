package org.springframework.security.oauth2.client.token;

import org.junit.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

import java.util.Arrays;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

/**
 * @author Marcos Barbero
 */
public abstract class ClientTokenServicesBaseTests {

    abstract ClientTokenServices getTokenServices();

    @Test
    public void testSaveAndRetrieveToken() throws Exception {
        OAuth2AccessToken accessToken = new DefaultOAuth2AccessToken("FOO");
        Authentication authentication = new UsernamePasswordAuthenticationToken("marissa",
                "koala");
        AuthorizationCodeResourceDetails resource = new AuthorizationCodeResourceDetails();
        resource.setClientId("client");
        resource.setScope(Arrays.asList("foo", "bar"));
        getTokenServices().saveAccessToken(resource, authentication, accessToken);
        OAuth2AccessToken result = getTokenServices().getAccessToken(resource,
                authentication);
        assertEquals(accessToken, result);
    }

    @Test
    public void testSaveAndRetrieveTokenForClientCredentials() throws Exception {
        OAuth2AccessToken accessToken = new DefaultOAuth2AccessToken("FOO");
        AuthorizationCodeResourceDetails resource = new AuthorizationCodeResourceDetails();
        resource.setClientId("client");
        resource.setScope(Arrays.asList("foo", "bar"));
        getTokenServices().saveAccessToken(resource, null, accessToken);
        OAuth2AccessToken result = getTokenServices().getAccessToken(resource, null);
        assertEquals(accessToken, result);
    }

    @Test
    public void testSaveAndRemoveToken() throws Exception {
        OAuth2AccessToken accessToken = new DefaultOAuth2AccessToken("FOO");
        Authentication authentication = new UsernamePasswordAuthenticationToken("marissa",
                "koala");
        AuthorizationCodeResourceDetails resource = new AuthorizationCodeResourceDetails();
        resource.setClientId("client");
        resource.setScope(Arrays.asList("foo", "bar"));
        getTokenServices().saveAccessToken(resource, authentication, accessToken);
        getTokenServices().removeAccessToken(resource, authentication);
        OAuth2AccessToken result = getTokenServices().getAccessToken(resource,
                authentication);
        assertNull(result);
    }
}
