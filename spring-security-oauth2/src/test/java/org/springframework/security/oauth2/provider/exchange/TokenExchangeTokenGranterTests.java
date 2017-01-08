package org.springframework.security.oauth2.provider.exchange;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.*;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.when;

/**
 * Created on 8/1/17.
 *
 * @author Ryan Murfitt (ryan.murfitt@console.com.au)
 */
@RunWith(MockitoJUnitRunner.class)
public class TokenExchangeTokenGranterTests {

    private Authentication validUser = new UsernamePasswordAuthenticationToken("foo", "bar",
            Arrays.asList(new SimpleGrantedAuthority("ROLE_USER")));

    private BaseClientDetails client = new BaseClientDetails("foo", "resource", "scope", "token-exchange", "ROLE_USER");

    @Mock
    private TokenExchangeService tokenExchangeService;

    private DefaultTokenServices providerTokenServices = new DefaultTokenServices();

    private ClientDetailsService clientDetailsService = new ClientDetailsService() {
        public ClientDetails loadClientByClientId(String clientId) throws OAuth2Exception {
            return client;
        }
    };

    private OAuth2RequestFactory requestFactory = new DefaultOAuth2RequestFactory(clientDetailsService);

    private TokenExchangeTokenGranter granter;

    private TokenRequest tokenRequest;

    @Before
    public void setup() {
        when(this.tokenExchangeService.loadUserAuthFromToken(any(TokenExchangeAuthenticationToken.class))).thenReturn(this.validUser);

        String clientId = "client";
        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId(clientId);

        providerTokenServices.setTokenStore(new InMemoryTokenStore());
        Map<String, String> parameters = new HashMap<String, String>();
        parameters.put("subject_token", "token123");
        parameters.put("subject_type", "bearer");

        granter = new TokenExchangeTokenGranter(tokenExchangeService,
                providerTokenServices, clientDetailsService, requestFactory);

        tokenRequest = requestFactory.createTokenRequest(parameters, clientDetails);
    }

    @Test
    public void testSuccessfulGrant() {
        OAuth2AccessToken token = granter.grant("token-exchange", tokenRequest);
        OAuth2Authentication authentication = providerTokenServices.loadAuthentication(token.getValue());
        assertTrue(authentication.isAuthenticated());
    }

    @Test(expected = InvalidClientException.class)
    public void testGrantTypeNotSupported() {
        client.setAuthorizedGrantTypes(Collections.singleton("client_credentials"));
        granter.grant("token-exchange", tokenRequest);
    }

    @Test(expected = InvalidGrantException.class)
    public void testInvalidToken() {
        when(this.tokenExchangeService.loadUserAuthFromToken(any(TokenExchangeAuthenticationToken.class))).thenThrow(new InvalidTokenException("invalid token"));
        granter.grant("token-exchange", tokenRequest);
    }

    @Test(expected = InvalidGrantException.class)
    public void testAccountLocked() {
        when(this.tokenExchangeService.loadUserAuthFromToken(any(TokenExchangeAuthenticationToken.class))).thenThrow(new LockedException("locked"));
        granter.grant("token-exchange", tokenRequest);
    }

    @Test(expected = InvalidGrantException.class)
    public void testUnauthenticated() {
        validUser = new UsernamePasswordAuthenticationToken("foo", "bar");
        when(this.tokenExchangeService.loadUserAuthFromToken(any(TokenExchangeAuthenticationToken.class))).thenReturn(this.validUser);
        granter.grant("token-exchange", tokenRequest);
    }
}