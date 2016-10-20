package org.springframework.security.oauth2.provider.token;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.common.util.MapDigester;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.mockito.Matchers.anyMap;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class DefaultAuthenticationKeyGeneratorTest {
    private static final String USERNAME = "name";
    private static final String CLIENT_ID = "client-id";
    private static final String CHECKSUM = "checksum";
    @Mock
    private OAuth2Authentication auth;
    @Mock
    private MapDigester mapDigester;
    @InjectMocks
    private DefaultAuthenticationKeyGenerator generator;

    @Before
    public void setUp() throws Exception {
        when(auth.getName()).thenReturn(USERNAME);
        when(mapDigester.digest(anyMap())).thenReturn(CHECKSUM);
    }

    @Test
    public void shouldUseTheChecksumGeneratedByTheDigest() {
        when(auth.getOAuth2Request()).thenReturn(newOauthRequest(CLIENT_ID));
        when(mapDigester.digest(anyMap())).thenReturn(CHECKSUM);

        assertEquals(CHECKSUM, generator.extractKey(auth));
    }

    @Test
    public void shouldOnlyUseTheUsernameAsPartOfTheDigestIfTheAuthIsClientOnly() {
        when(auth.isClientOnly()).thenReturn(true);
        when(auth.getOAuth2Request()).thenReturn(newOauthRequest(CLIENT_ID));

        generator.extractKey(auth);

        LinkedHashMap<String, String> expectedValues = new LinkedHashMap<String, String>();
        expectedValues.put("client_id", CLIENT_ID);
        expectedValues.put("scope", "");
        verify(mapDigester).digest(expectedValues);
    }

    @Test
    public void shouldNotUseScopesIfNoneAreProvided() {
        when(auth.getOAuth2Request()).thenReturn(newOauthRequest(CLIENT_ID));

        generator.extractKey(auth);

        LinkedHashMap<String, String> expectedValues = new LinkedHashMap<String, String>();
        expectedValues.put("username", USERNAME);
        expectedValues.put("client_id", CLIENT_ID);
        expectedValues.put("scope", "");
        verify(mapDigester).digest(expectedValues);
    }

    @Test
    public void shouldSortTheScopesBeforeDigesting() {
        when(auth.getOAuth2Request()).thenReturn(newOauthRequest(CLIENT_ID, "3", "1", "2"));

        generator.extractKey(auth);

        LinkedHashMap<String, String> expectedValues = new LinkedHashMap<String, String>();
        expectedValues.put("username", USERNAME);
        expectedValues.put("client_id", CLIENT_ID);
        expectedValues.put("scope", "1 2 3");
        verify(mapDigester).digest(expectedValues);
    }

    private OAuth2Request newOauthRequest(String clientId, String... scopes) {
        Set<String> scopeSet = new LinkedHashSet<String>(Arrays.asList(scopes));
        if (scopes.length == 0) {
            scopeSet = null;
        }

        return new OAuth2Request(
                new HashMap<String, String>(),
                clientId,
                new ArrayList<GrantedAuthority>(),
                true,
                scopeSet,
                new HashSet<String>(),
                "redirect-uri",
                new HashSet<String>(),
                new HashMap<String, Serializable>()
        );
    }
}