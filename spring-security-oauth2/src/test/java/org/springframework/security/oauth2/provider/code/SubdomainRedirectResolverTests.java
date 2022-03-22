package org.springframework.security.oauth2.provider.code;

import static org.junit.jupiter.api.Assertions.assertEquals;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.common.exceptions.RedirectMismatchException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.endpoint.DefaultRedirectResolver;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SubdomainRedirectResolverTests {

    private DefaultRedirectResolver resolver;

    private final BaseClientDetails client = new BaseClientDetails();

    {
        client.setAuthorizedGrantTypes(Collections.singleton("authorization_code"));
    }

    @BeforeEach
    void setup() {
        resolver = new DefaultRedirectResolver();
    }

    @Test
    void testRedirectMatch() throws Exception {
        resolver.setMatchSubdomains(true);
        Set<String> redirectUris = new HashSet<String>(Arrays.asList("https://watchdox.com"));
        client.setRegisteredRedirectUri(redirectUris);
        String requestedRedirect = "https://anywhere.watchdox.com";
        assertEquals(requestedRedirect, resolver.resolveRedirect(requestedRedirect, client));
    }

    @Test
    void testRedirectNoMatch() throws Exception {
        assertThrows(RedirectMismatchException.class, () -> {
            Set<String> redirectUris = new HashSet<String>(Arrays.asList("https://watchdox.com"));
            client.setRegisteredRedirectUri(redirectUris);
            String requestedRedirect = "https://anywhere.google.com";
            assertEquals(requestedRedirect, resolver.resolveRedirect(requestedRedirect, client));
        });
    }
}
