package org.springframework.security.oauth2.provider;

import java.util.Arrays;
import java.util.Collections;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.test.annotation.Rollback;
import org.springframework.util.SerializationUtils;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OAuth2AuthenticationTests {

    private OAuth2Request request = RequestTokenFactory.createOAuth2Request(null, "id", null, false, Collections.singleton("read"), null, null, null, null);

    private UsernamePasswordAuthenticationToken userAuthentication = new UsernamePasswordAuthenticationToken("foo", "bar", Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")));

    @Test
    @Rollback
    void testIsAuthenticated() {
        request = RequestTokenFactory.createOAuth2Request("id", true, Collections.singleton("read"));
        OAuth2Authentication authentication = new OAuth2Authentication(request, userAuthentication);
        assertTrue(authentication.isAuthenticated());
    }

    @Test
    void testGetCredentials() {
        OAuth2Authentication authentication = new OAuth2Authentication(request, userAuthentication);
        assertEquals("", authentication.getCredentials());
    }

    @Test
    void testGetPrincipal() {
        OAuth2Authentication authentication = new OAuth2Authentication(request, userAuthentication);
        assertEquals(userAuthentication.getPrincipal(), authentication.getPrincipal());
    }

    @Test
    void testIsClientOnly() {
        OAuth2Authentication authentication = new OAuth2Authentication(request, null);
        assertTrue(authentication.isClientOnly());
    }

    @Test
    void testJsonSerialization() throws Exception {
        System.err.println(new ObjectMapper().writeValueAsString(new OAuth2Authentication(request, userAuthentication)));
    }

    @Test
    void testSerialization() {
        OAuth2Authentication holder = new OAuth2Authentication(new AuthorizationRequest("client", Arrays.asList("read")).createOAuth2Request(), new UsernamePasswordAuthenticationToken("user", "pwd"));
        OAuth2Authentication other = (OAuth2Authentication) SerializationUtils.deserialize(SerializationUtils.serialize(holder));
        assertEquals(holder, other);
    }

    @Test
    void testSerializationWithDetails() {
        OAuth2Authentication holder = new OAuth2Authentication(new AuthorizationRequest("client", Arrays.asList("read")).createOAuth2Request(), new UsernamePasswordAuthenticationToken("user", "pwd"));
        holder.setDetails(new OAuth2AuthenticationDetails(new MockHttpServletRequest()));
        OAuth2Authentication other = (OAuth2Authentication) SerializationUtils.deserialize(SerializationUtils.serialize(holder));
        assertEquals(holder, other);
    }

    // gh-573
    @Test
    void testEraseCredentialsUserAuthentication() {
        OAuth2Authentication authentication = new OAuth2Authentication(request, userAuthentication);
        authentication.eraseCredentials();
        assertNull(authentication.getUserAuthentication().getCredentials());
    }
}
