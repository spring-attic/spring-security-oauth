/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.provider.endpoint;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.common.exceptions.RedirectMismatchException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * @author Dave Syer
 */
class DefaultRedirectResolverTests {

    private DefaultRedirectResolver resolver;

    private BaseClientDetails client;

    @BeforeEach
    void setup() {
        client = new BaseClientDetails();
        client.setAuthorizedGrantTypes(Collections.singleton("authorization_code"));
        resolver = new DefaultRedirectResolver();
    }

    @Test
    void testRedirectMatchesRegisteredValue() throws Exception {
        Set<String> redirectUris = new HashSet<String>(Arrays.asList("https://anywhere.com"));
        client.setRegisteredRedirectUri(redirectUris);
        String requestedRedirect = "https://anywhere.com";
        assertEquals(requestedRedirect, resolver.resolveRedirect(requestedRedirect, client));
    }

    @Test
    void testRedirectWithNoRegisteredValue() throws Exception {
        assertThrows(InvalidRequestException.class, () -> {
            String requestedRedirect = "https://anywhere.com/myendpoint";
            resolver.resolveRedirect(requestedRedirect, client);
        });
    }

    // If only one redirect has been registered, then we should use it
    @Test
    void testRedirectWithNoRequestedValue() throws Exception {
        Set<String> redirectUris = new HashSet<String>(Arrays.asList("https://anywhere.com"));
        client.setRegisteredRedirectUri(redirectUris);
        resolver.resolveRedirect(null, client);
    }

    // If multiple redirects registered, then we should get an exception
    @Test
    void testRedirectWithNoRequestedValueAndMultipleRegistered() throws Exception {
        assertThrows(RedirectMismatchException.class, () -> {
            Set<String> redirectUris = new HashSet<String>(Arrays.asList("https://anywhere.com", "https://nowhere.com"));
            client.setRegisteredRedirectUri(redirectUris);
            resolver.resolveRedirect(null, client);
        });
    }

    @Test
    void testNoGrantType() throws Exception {
        assertThrows(InvalidGrantException.class, () -> {
            Set<String> redirectUris = new HashSet<String>(Arrays.asList("https://anywhere.com", "https://nowhere.com"));
            client.setRegisteredRedirectUri(redirectUris);
            client.setAuthorizedGrantTypes(Collections.<String>emptyList());
            resolver.resolveRedirect(null, client);
        });
    }

    @Test
    void testWrongGrantType() throws Exception {
        assertThrows(InvalidGrantException.class, () -> {
            Set<String> redirectUris = new HashSet<String>(Arrays.asList("https://anywhere.com", "https://nowhere.com"));
            client.setRegisteredRedirectUri(redirectUris);
            client.setAuthorizedGrantTypes(Collections.singleton("client_credentials"));
            resolver.resolveRedirect(null, client);
        });
    }

    @Test
    void testWrongCustomGrantType() throws Exception {
        assertThrows(InvalidGrantException.class, () -> {
            resolver.setRedirectGrantTypes(Collections.singleton("foo"));
            Set<String> redirectUris = new HashSet<String>(Arrays.asList("https://anywhere.com", "https://nowhere.com"));
            client.setRegisteredRedirectUri(redirectUris);
            resolver.resolveRedirect(null, client);
        });
    }

    @Test
    void testRedirectNotMatching() throws Exception {
        assertThrows(RedirectMismatchException.class, () -> {
            Set<String> redirectUris = new HashSet<String>(Arrays.asList("https://nowhere.com"));
            String requestedRedirect = "https://anywhere.com/myendpoint";
            client.setRegisteredRedirectUri(redirectUris);
            assertEquals(redirectUris.iterator().next(), resolver.resolveRedirect(requestedRedirect, client));
        });
    }

    @Test
    void testRedirectNotMatchingWithTraversal() throws Exception {
        assertThrows(RedirectMismatchException.class, () -> {
            Set<String> redirectUris = new HashSet<String>(Arrays.asList("https://anywhere.com/foo"));
            String requestedRedirect = "https://anywhere.com/foo/../bar";
            client.setRegisteredRedirectUri(redirectUris);
            assertEquals(redirectUris.iterator().next(), resolver.resolveRedirect(requestedRedirect, client));
        });
    }

    // gh-1331
    @Test
    void testRedirectNotMatchingWithHexEncodedTraversal() throws Exception {
        assertThrows(RedirectMismatchException.class, () -> {
            Set<String> redirectUris = new HashSet<String>(Arrays.asList("https://anywhere.com/foo"));
            client.setRegisteredRedirectUri(redirectUris);
            // hexadecimal encoding of '..' represents '%2E%2E'
            String requestedRedirect = "https://anywhere.com/foo/%2E%2E";
            resolver.resolveRedirect(requestedRedirect, client);
        });
    }

    // gh-747
    @Test
    void testRedirectNotMatchingSubdomain() throws Exception {
        assertThrows(RedirectMismatchException.class, () -> {
            Set<String> redirectUris = new HashSet<String>(Arrays.asList("https://anywhere.com/foo"));
            client.setRegisteredRedirectUri(redirectUris);
            resolver.resolveRedirect("https://2anywhere.com/foo", client);
        });
    }

    // gh-747
    // gh-747
    @Test
    void testRedirectMatchingSubdomain() throws Exception {
        resolver.setMatchSubdomains(true);
        Set<String> redirectUris = new HashSet<String>(Arrays.asList("https://anywhere.com/foo"));
        String requestedRedirect = "https://2.anywhere.com/foo";
        client.setRegisteredRedirectUri(redirectUris);
        assertEquals(requestedRedirect, resolver.resolveRedirect(requestedRedirect, client));
    }

    @Test
    void testRedirectMatchSubdomainsDefaultsFalse() {
        assertThrows(RedirectMismatchException.class, () -> {
            Set<String> redirectUris = new HashSet<String>(Arrays.asList("https://anywhere.com"));
            client.setRegisteredRedirectUri(redirectUris);
            resolver.resolveRedirect("https://2.anywhere.com", client);
        });
    }

    // gh-746
    @Test
    void testRedirectNotMatchingPort() throws Exception {
        assertThrows(RedirectMismatchException.class, () -> {
            Set<String> redirectUris = new HashSet<String>(Arrays.asList("https://anywhere.com:90"));
            client.setRegisteredRedirectUri(redirectUris);
            resolver.resolveRedirect("https://anywhere.com:91/foo", client);
        });
    }

    // gh-746
    @Test
    void testRedirectMatchingPort() throws Exception {
        Set<String> redirectUris = new HashSet<String>(Arrays.asList("https://anywhere.com:90"));
        client.setRegisteredRedirectUri(redirectUris);
        String requestedRedirect = "https://anywhere.com:90";
        assertEquals(requestedRedirect, resolver.resolveRedirect(requestedRedirect, client));
    }

    // gh-746
    @Test
    void testRedirectRegisteredPortSetRequestedPortNotSet() throws Exception {
        assertThrows(RedirectMismatchException.class, () -> {
            Set<String> redirectUris = new HashSet<String>(Arrays.asList("https://anywhere.com:90"));
            client.setRegisteredRedirectUri(redirectUris);
            resolver.resolveRedirect("https://anywhere.com/foo", client);
        });
    }

    // gh-746
    @Test
    void testRedirectRegisteredPortNotSetRequestedPortSet() throws Exception {
        assertThrows(RedirectMismatchException.class, () -> {
            Set<String> redirectUris = new HashSet<String>(Arrays.asList("https://anywhere.com"));
            client.setRegisteredRedirectUri(redirectUris);
            resolver.resolveRedirect("https://anywhere.com:8443/foo", client);
        });
    }

    // gh-746
    @Test
    void testRedirectMatchPortsFalse() throws Exception {
        resolver.setMatchPorts(false);
        Set<String> redirectUris = new HashSet<String>(Arrays.asList("https://anywhere.com:90"));
        client.setRegisteredRedirectUri(redirectUris);
        String requestedRedirect = "https://anywhere.com:91";
        assertEquals(requestedRedirect, resolver.resolveRedirect(requestedRedirect, client));
    }

    // gh-1386
    @Test
    void testRedirectNotMatchingReturnsGenericErrorMessage() throws Exception {
        Set<String> redirectUris = new HashSet<String>(Arrays.asList("https://nowhere.com"));
        String requestedRedirect = "https://anywhere.com/myendpoint";
        client.setRegisteredRedirectUri(redirectUris);
        try {
            resolver.resolveRedirect(requestedRedirect, client);
            fail();
        } catch (RedirectMismatchException ex) {
            assertEquals("Invalid redirect uri does not match one of the registered values.", ex.getMessage());
        }
    }

    // gh-1566
    @Test
    void testRedirectRegisteredUserInfoNotMatching() throws Exception {
        assertThrows(RedirectMismatchException.class, () -> {
            Set<String> redirectUris = new HashSet<String>(Arrays.asList("https://userinfo@anywhere.com"));
            client.setRegisteredRedirectUri(redirectUris);
            resolver.resolveRedirect("https://otheruserinfo@anywhere.com", client);
        });
    }

    // gh-1566
    @Test
    void testRedirectRegisteredNoUserInfoNotMatching() throws Exception {
        assertThrows(RedirectMismatchException.class, () -> {
            Set<String> redirectUris = new HashSet<String>(Arrays.asList("https://userinfo@anywhere.com"));
            client.setRegisteredRedirectUri(redirectUris);
            resolver.resolveRedirect("https://anywhere.com", client);
        });
    }

    // gh-1566
    @Test
    void testRedirectRegisteredUserInfoMatching() throws Exception {
        Set<String> redirectUris = new HashSet<String>(Arrays.asList("https://userinfo@anywhere.com"));
        client.setRegisteredRedirectUri(redirectUris);
        String requestedRedirect = "https://userinfo@anywhere.com";
        assertEquals(requestedRedirect, resolver.resolveRedirect(requestedRedirect, client));
    }

    // gh-1566
    @Test
    void testRedirectRegisteredFragmentIgnoredAndStripped() throws Exception {
        Set<String> redirectUris = new HashSet<String>(Arrays.asList("https://userinfo@anywhere.com/foo/bar#baz"));
        client.setRegisteredRedirectUri(redirectUris);
        String requestedRedirect = "https://userinfo@anywhere.com/foo/bar";
        assertEquals(requestedRedirect, resolver.resolveRedirect(requestedRedirect + "#bar", client));
    }

    // gh-1566
    @Test
    void testRedirectRegisteredQueryParamsMatching() throws Exception {
        Set<String> redirectUris = new HashSet<String>(Arrays.asList("https://anywhere.com/?p1=v1&p2=v2"));
        client.setRegisteredRedirectUri(redirectUris);
        String requestedRedirect = "https://anywhere.com/?p1=v1&p2=v2";
        assertEquals(requestedRedirect, resolver.resolveRedirect(requestedRedirect, client));
    }

    // gh-1566
    @Test
    void testRedirectRegisteredQueryParamsMatchingIgnoringAdditionalParams() throws Exception {
        Set<String> redirectUris = new HashSet<String>(Arrays.asList("https://anywhere.com/?p1=v1&p2=v2"));
        client.setRegisteredRedirectUri(redirectUris);
        String requestedRedirect = "https://anywhere.com/?p1=v1&p2=v2&p3=v3";
        assertEquals(requestedRedirect, resolver.resolveRedirect(requestedRedirect, client));
    }

    // gh-1566
    @Test
    void testRedirectRegisteredQueryParamsMatchingDifferentOrder() throws Exception {
        Set<String> redirectUris = new HashSet<String>(Arrays.asList("https://anywhere.com/?p1=v1&p2=v2"));
        client.setRegisteredRedirectUri(redirectUris);
        String requestedRedirect = "https://anywhere.com/?p2=v2&p1=v1";
        assertEquals(requestedRedirect, resolver.resolveRedirect(requestedRedirect, client));
    }

    // gh-1566
    @Test
    void testRedirectRegisteredQueryParamsWithDifferentValues() throws Exception {
        assertThrows(RedirectMismatchException.class, () -> {
            Set<String> redirectUris = new HashSet<String>(Arrays.asList("https://anywhere.com/?p1=v1&p2=v2"));
            client.setRegisteredRedirectUri(redirectUris);
            resolver.resolveRedirect("https://anywhere.com/?p1=v1&p2=v3", client);
        });
    }

    // gh-1566
    @Test
    void testRedirectRegisteredQueryParamsNotMatching() throws Exception {
        assertThrows(RedirectMismatchException.class, () -> {
            Set<String> redirectUris = new HashSet<String>(Arrays.asList("https://anywhere.com/?p1=v1"));
            client.setRegisteredRedirectUri(redirectUris);
            resolver.resolveRedirect("https://anywhere.com/?p2=v2", client);
        });
    }

    // gh-1566
    @Test
    void testRedirectRegisteredQueryParamsPartiallyMatching() throws Exception {
        assertThrows(RedirectMismatchException.class, () -> {
            Set<String> redirectUris = new HashSet<String>(Arrays.asList("https://anywhere.com/?p1=v1&p2=v2"));
            client.setRegisteredRedirectUri(redirectUris);
            resolver.resolveRedirect("https://anywhere.com/?p2=v2&p3=v3", client);
        });
    }

    // gh-1566
    @Test
    void testRedirectRegisteredQueryParamsMatchingWithMultipleValuesInRegistered() throws Exception {
        Set<String> redirectUris = new HashSet<String>(Arrays.asList("https://anywhere.com/?p1=v11&p1=v12"));
        client.setRegisteredRedirectUri(redirectUris);
        String requestedRedirect = "https://anywhere.com/?p1=v11&p1=v12";
        assertEquals(requestedRedirect, resolver.resolveRedirect(requestedRedirect, client));
    }

    // gh-1566
    @Test
    void testRedirectRegisteredQueryParamsMatchingWithParamWithNoValue() throws Exception {
        Set<String> redirectUris = new HashSet<String>(Arrays.asList("https://anywhere.com/?p1&p2=v2"));
        client.setRegisteredRedirectUri(redirectUris);
        String requestedRedirect = "https://anywhere.com/?p1&p2=v2";
        assertEquals(requestedRedirect, resolver.resolveRedirect(requestedRedirect, client));
    }

    // gh-1618
    @Test
    void testRedirectNoHost() {
        Set<String> redirectUris = new HashSet<String>(Arrays.asList("scheme:/path"));
        client.setRegisteredRedirectUri(redirectUris);
        String requestedRedirect = "scheme:/path";
        assertEquals(requestedRedirect, resolver.resolveRedirect(requestedRedirect, client));
    }
}
