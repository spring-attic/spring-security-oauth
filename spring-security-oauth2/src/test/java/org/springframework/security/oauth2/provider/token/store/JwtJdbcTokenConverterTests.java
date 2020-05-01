package org.springframework.security.oauth2.provider.token.store;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.oauth2.common.DefaultExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.DefaultOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.util.JsonParser;
import org.springframework.security.oauth2.common.util.JsonParserFactory;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.token.AccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverterTests.TestAuthentication;

import java.util.*;

import static org.junit.Assert.*;

public class JwtJdbcTokenConverterTests {

    private JwtJdbcTokenConverter tokenEnhancer;

    private Authentication userAuthentication;

    @Before
    public void setUp() throws Exception {
        tokenEnhancer = new JwtJdbcTokenConverter();
        userAuthentication = new TestAuthentication("test2", true);
    }
    
    @Test
    public void testRefreshTokenAdded() throws Exception {
        OAuth2Authentication authentication = new OAuth2Authentication(
                createOAuth2Request("foo", Collections.singleton("read")),
                userAuthentication);
        DefaultOAuth2AccessToken original = new DefaultOAuth2AccessToken("FOO");
        original.setScope(authentication.getOAuth2Request().getScope());
        original.setRefreshToken(new DefaultOAuth2RefreshToken("BAR"));
        original.setExpiration(new Date());
        OAuth2AccessToken token = tokenEnhancer.enhance(original, authentication);
        assertNotNull(token.getValue());
        assertNotNull(token.getRefreshToken());
        JsonParser parser = JsonParserFactory.create();
        Map<String, Object> claims = parser.parseMap(JwtHelper.decode(
                token.getRefreshToken().getValue()).getClaims());
        assertEquals(Arrays.asList("read"), claims.get(AccessTokenConverter.SCOPE));
        assertEquals("FOO", claims.get(AccessTokenConverter.ATI));
        assertEquals("BAR", claims.get(AccessTokenConverter.JTI));
        assertNull(claims.get(AccessTokenConverter.EXP));
        tokenEnhancer.afterPropertiesSet();
        assertTrue(tokenEnhancer.isRefreshToken(tokenEnhancer.extractAccessToken(token
                .getRefreshToken().getValue(), tokenEnhancer.decode(token
                .getRefreshToken().getValue()))));
    }

    @Test
    public void testExpiringRefreshTokenAdded() throws Exception {
        OAuth2Authentication authentication = new OAuth2Authentication(
                createOAuth2Request("foo", Collections.singleton("read")),
                userAuthentication);
        DefaultOAuth2AccessToken original = new DefaultOAuth2AccessToken("FOO");
        original.setScope(authentication.getOAuth2Request().getScope());
        original.setRefreshToken(new DefaultExpiringOAuth2RefreshToken("BAR", new Date(0)));
        original.setExpiration(new Date());
        OAuth2AccessToken token = tokenEnhancer.enhance(original, authentication);
        assertNotNull(token.getValue());
        assertNotNull(token.getRefreshToken());
        JsonParser parser = JsonParserFactory.create();
        Map<String, Object> claims = parser.parseMap(JwtHelper.decode(
                token.getRefreshToken().getValue()).getClaims());
        assertEquals(Arrays.asList("read"), claims.get(AccessTokenConverter.SCOPE));
        assertEquals("FOO", claims.get(AccessTokenConverter.ATI));
        assertEquals("BAR", claims.get(AccessTokenConverter.JTI));
        assertEquals(0, claims.get(AccessTokenConverter.EXP));
        tokenEnhancer.afterPropertiesSet();
        assertTrue(tokenEnhancer.isRefreshToken(tokenEnhancer.extractAccessToken(token
                .getRefreshToken().getValue(), tokenEnhancer.decode(token
                .getRefreshToken().getValue()))));
    }

    @Test
    public void testRefreshTokenAccessTokenIdWhenDoubleEnhanced() throws Exception {
        OAuth2Authentication authentication = new OAuth2Authentication(
                createOAuth2Request("foo", Collections.singleton("read")),
                userAuthentication);
        DefaultOAuth2AccessToken original = new DefaultOAuth2AccessToken("FOO");
        original.setScope(authentication.getOAuth2Request().getScope());
        original.setRefreshToken(new DefaultOAuth2RefreshToken("BAR"));
        OAuth2AccessToken token = tokenEnhancer.enhance(original, authentication);
        token = tokenEnhancer.enhance(token, authentication);
        assertNotNull(token.getValue());
        assertNotNull(token.getRefreshToken());
        JsonParser parser = JsonParserFactory.create();
        Map<String, Object> claims = parser.parseMap(JwtHelper.decode(
                token.getRefreshToken().getValue()).getClaims());
        assertEquals(Arrays.asList("read"), claims.get(AccessTokenConverter.SCOPE));
        assertEquals("FOO", claims.get(AccessTokenConverter.ATI));
        assertEquals("Wrong claims: " + claims, "BAR", claims.get(AccessTokenConverter.JTI));
    }
    
    private OAuth2Request createOAuth2Request(String clientId, Set<String> scope) {
        return new OAuth2Request(Collections.<String, String> emptyMap(), clientId, null,
                true, scope, null, null, null, null);
    }
}
