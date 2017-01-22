package org.springframework.security.oauth2.provider.exchange;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.provider.ClientDetails;

import java.util.Collection;

/**
 * Token that represents a token-exchange authentication request.
 *
 * Similar to {@link org.springframework.security.authentication.UsernamePasswordAuthenticationToken} where the principal
 * represents the 'subject_token', but once authenticated, the principal represents the user, and the credentials represents
 * the 'subject_token'.
 *
 * @author Ryan Murfitt
 */
public class TokenExchangeAuthenticationToken extends AbstractAuthenticationToken {

    private final Object principal;
    private final ClientDetails clientDetails;
    private final Object credentials;

    TokenExchangeAuthenticationToken(Object principal, ClientDetails clientDetails) {
        super(null);
        this.principal = principal;
        this.credentials = null;
        this.clientDetails = clientDetails;
        this.setAuthenticated(false);
    }

    TokenExchangeAuthenticationToken(Object principal, Object credentials, ClientDetails clientDetails, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        this.credentials = credentials;
        this.clientDetails = clientDetails;
        this.setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return credentials;
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }

    public ClientDetails getClientDetails() {
        return clientDetails;
    }
}
