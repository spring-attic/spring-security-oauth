package org.springframework.security.oauth2.provider.exchange;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.Assert;

/**
 * {@link AuthenticationProvider} that supports {@link TokenExchangeAuthenticationToken}.
 *
 * @author Ryan Murfitt
 */
public class DefaultTokenExchangeAuthenticationProvider implements AuthenticationProvider {

    private TokenExchangeService tokenExchangeService;
    private GrantedAuthoritiesMapper authoritiesMapper = new NullAuthoritiesMapper();

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        Assert.isInstanceOf(TokenExchangeAuthenticationToken.class, authentication, "Only TokenExchangeAuthenticationToken is supported");
        UserDetails user = this.tokenExchangeService.loadUserDetailsFromToken((TokenExchangeAuthenticationToken) authentication);
        return createSuccessAuthentication(user, (TokenExchangeAuthenticationToken) authentication);
    }

    private Authentication createSuccessAuthentication(UserDetails user, TokenExchangeAuthenticationToken token) {
        TokenExchangeAuthenticationToken result = new TokenExchangeAuthenticationToken(user, token.getPrincipal(), token.getClientDetails(), this.authoritiesMapper.mapAuthorities(user.getAuthorities()));
        result.setDetails(token.getDetails());
        return result;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return TokenExchangeAuthenticationToken.class.isAssignableFrom(authentication);
    }

    public void setTokenExchangeService(TokenExchangeService tokenExchangeService) {
        this.tokenExchangeService = tokenExchangeService;
    }

    public void setAuthoritiesMapper(GrantedAuthoritiesMapper authoritiesMapper) {
        this.authoritiesMapper = authoritiesMapper;
    }
}
