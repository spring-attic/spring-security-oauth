package org.springframework.security.oauth2.provider.vote;

import static org.junit.jupiter.api.Assertions.assertEquals;
import java.util.Arrays;
import java.util.Collections;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.client.InMemoryClientDetailsService;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ClientScopeVoterTests {

    private ClientScopeVoter voter = new ClientScopeVoter();

    private Authentication userAuthentication = new UsernamePasswordAuthenticationToken("user", "password", AuthorityUtils.commaSeparatedStringToAuthorityList("read,write"));

    private OAuth2Authentication authentication;

    private BaseClientDetails client;

    @BeforeEach
    void init() {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest();
        authorizationRequest.setClientId("client");
        authorizationRequest.setScope(Arrays.asList("read", "write"));
        authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        InMemoryClientDetailsService clientDetailsService = new InMemoryClientDetailsService();
        client = new BaseClientDetails("client", "source", "read,write", "authorization_code,client_credentials", "read");
        clientDetailsService.setClientDetailsStore(Collections.singletonMap("client", client));
        voter.setClientDetailsService(clientDetailsService);
    }

    @Test
    void testAccessGranted() {
        assertEquals(AccessDecisionVoter.ACCESS_GRANTED, voter.vote(authentication, null, Arrays.<ConfigAttribute>asList(new SecurityConfig("CLIENT_HAS_SCOPE"))));
    }

    @Test
    void testAccessDenied() {
        assertThrows(AccessDeniedException.class, () -> {
            client.setScope(Arrays.asList("none"));
            assertEquals(AccessDecisionVoter.ACCESS_DENIED, voter.vote(authentication, null, Arrays.<ConfigAttribute>asList(new SecurityConfig("CLIENT_HAS_SCOPE"))));
        });
    }

    @Test
    void testAccessDeniedNoException() {
        voter.setThrowException(false);
        client.setScope(Arrays.asList("none"));
        assertEquals(AccessDecisionVoter.ACCESS_DENIED, voter.vote(authentication, null, Arrays.<ConfigAttribute>asList(new SecurityConfig("CLIENT_HAS_SCOPE"))));
    }
}
