package org.springframework.security.oauth2.provider.token;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsByNameServiceWrapper;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.DefaultOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import java.util.Arrays;
import static org.junit.jupiter.api.Assertions.assertThrows;

class DefaultTokenServicesTests {

    private DefaultTokenServices services;

    private TokenStore tokenStore = Mockito.mock(TokenStore.class);

    @BeforeEach
    void init() throws Exception {
        services = new DefaultTokenServices();
        services.setTokenStore(tokenStore);
        services.afterPropertiesSet();
    }

    @Test
    void testAccidentalNullAuthentication() {
        assertThrows(InvalidTokenException.class, () -> {
            Mockito.when(tokenStore.readAccessToken(Mockito.anyString())).thenReturn(new DefaultOAuth2AccessToken("FOO"));
            // A bug in the TokenStore or a race condition could lead to the authentication
            // being null even if the token is not:
            Mockito.when(tokenStore.readAuthentication(Mockito.any(OAuth2AccessToken.class))).thenReturn(null);
            services.loadAuthentication("FOO");
        });
        // A bug in the TokenStore or a race condition could lead to the authentication
    }

    @Test
    void testRefreshAccessTokenWithReauthentication() {
        UserDetails user = createMockUser("joeuser", "PROCESSOR");
        UserDetailsService userDetailsService = Mockito.mock(UserDetailsService.class);
        Mockito.when(tokenStore.readRefreshToken(Mockito.anyString())).thenReturn(new DefaultOAuth2RefreshToken("FOO"));
        Mockito.when(tokenStore.readAuthenticationForRefreshToken(Mockito.any(OAuth2RefreshToken.class))).thenReturn(createMockOAuth2Authentication("myclient", user, "some more details"));
        Mockito.when(userDetailsService.loadUserByUsername(Mockito.anyString())).thenReturn(user);
        services.setSupportRefreshToken(true);
        services.setAuthenticationManager(createAuthenticationManager(userDetailsService));
        OAuth2AccessToken refreshedAccessToken = services.refreshAccessToken("FOO", createMockTokenRequest("myclient"));
        ArgumentCaptor<OAuth2Authentication> refreshedAuthenticationCaptor = ArgumentCaptor.forClass(OAuth2Authentication.class);
        Mockito.verify(tokenStore).storeAccessToken(Mockito.eq(refreshedAccessToken), refreshedAuthenticationCaptor.capture());
        OAuth2Authentication refreshedAuthentication = refreshedAuthenticationCaptor.getValue();
        Authentication authentication = refreshedAuthentication.getUserAuthentication();
        Assertions.assertEquals(user, authentication.getPrincipal());
        Assertions.assertEquals("some more details", authentication.getDetails());
    }

    @Test
    void testRefreshAccessTokenWithoutReauthentication() {
        UserDetails user = createMockUser("joeuser", "PROCESSOR");
        Mockito.when(tokenStore.readRefreshToken(Mockito.anyString())).thenReturn(new DefaultOAuth2RefreshToken("FOO"));
        Mockito.when(tokenStore.readAuthenticationForRefreshToken(Mockito.any(OAuth2RefreshToken.class))).thenReturn(createMockOAuth2Authentication("myclient", user, "some more details"));
        services.setSupportRefreshToken(true);
        services.setAuthenticationManager(null);
        OAuth2AccessToken refreshedAccessToken = services.refreshAccessToken("FOO", createMockTokenRequest("myclient"));
        ArgumentCaptor<OAuth2Authentication> refreshedAuthenticationCaptor = ArgumentCaptor.forClass(OAuth2Authentication.class);
        Mockito.verify(tokenStore).storeAccessToken(Mockito.eq(refreshedAccessToken), refreshedAuthenticationCaptor.capture());
        OAuth2Authentication refreshedAuthentication = refreshedAuthenticationCaptor.getValue();
        Authentication authentication = refreshedAuthentication.getUserAuthentication();
        Assertions.assertEquals(user, authentication.getPrincipal());
        Assertions.assertEquals("some more details", authentication.getDetails());
    }

    private AuthenticationManager createAuthenticationManager(UserDetailsService userDetailsService) {
        PreAuthenticatedAuthenticationProvider provider = new PreAuthenticatedAuthenticationProvider();
        provider.setPreAuthenticatedUserDetailsService(new UserDetailsByNameServiceWrapper<PreAuthenticatedAuthenticationToken>(userDetailsService));
        return new ProviderManager(Arrays.<AuthenticationProvider>asList(provider));
    }

    private TokenRequest createMockTokenRequest(String clientId) {
        return new TokenRequest(null, clientId, null, null);
    }

    private OAuth2Request createMockOAuth2Request(String clientId) {
        return new OAuth2Request(null, clientId, null, true, null, null, null, null, null);
    }

    private OAuth2Authentication createMockOAuth2Authentication(String clientId, UserDetails user, String extraDetails) {
        return new OAuth2Authentication(createMockOAuth2Request(clientId), createMockUserAuthentication(user, extraDetails));
    }

    private UsernamePasswordAuthenticationToken createMockUserAuthentication(UserDetails user, Object extraDetails) {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(user, "", user.getAuthorities());
        token.setDetails(extraDetails);
        return token;
    }

    private UserDetails createMockUser(String username, String... roles) {
        return new User(username, "", AuthorityUtils.createAuthorityList(roles));
    }
}
