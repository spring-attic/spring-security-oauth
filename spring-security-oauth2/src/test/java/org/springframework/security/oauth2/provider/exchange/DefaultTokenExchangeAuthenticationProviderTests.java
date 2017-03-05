package org.springframework.security.oauth2.provider.exchange;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collections;

import static org.mockito.Mockito.*;

import static org.junit.Assert.*;

/**
 * @author Ryan Murfitt
 */
@RunWith(MockitoJUnitRunner.class)
public class DefaultTokenExchangeAuthenticationProviderTests {

    @Mock
    private TokenExchangeService tokenExchangeService;

    @InjectMocks
    private DefaultTokenExchangeAuthenticationProvider provider = new DefaultTokenExchangeAuthenticationProvider();

    @Rule
    public final ExpectedException exception = ExpectedException.none();

    @Test
    public void authenticateIncorrectTokenType() {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
                "rod", "KOala");
         exception.expect(IllegalArgumentException.class);
         exception.expectMessage("Only TokenExchangeAuthenticationToken is supported");

         provider.authenticate(token);

         verifyZeroInteractions(this.tokenExchangeService);
    }

    @Test
    public void authenticateSuccess() {
        TokenExchangeAuthenticationToken token = new TokenExchangeAuthenticationToken(
                "token", null);
        UserDetails user = new User("bob", "password", Collections.<GrantedAuthority>emptyList());

        when(tokenExchangeService.loadUserDetailsFromToken(token)).thenReturn(user);

        Authentication result = provider.authenticate(token);

        assertTrue(result instanceof TokenExchangeAuthenticationToken);
        assertTrue(result.isAuthenticated());
        assertSame(result.getPrincipal(), user);
        assertSame(result.getCredentials(), token.getPrincipal());
    }

    @Test
    public void supportsIncorrectTokenType() {
        assertFalse(provider.supports(UsernamePasswordAuthenticationToken.class));
    }

    @Test
    public void supportsSuccess() {
        assertTrue(provider.supports(TokenExchangeAuthenticationToken.class));
    }

}