package org.springframework.security.oauth2.provider.exchange;

import org.springframework.security.authentication.AbstractAuthenticationToken;

/**
 * @author Ryan Murfitt
 */
public class TokenExchangeAuthenticationToken extends AbstractAuthenticationToken {

    private final Object principal;
    private final String principalType;

    TokenExchangeAuthenticationToken(Object principal, String principalType) {
        super(null);
        this.principal = principal;
        this.principalType = principalType;
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return this.principal;
    }

    public String getPrincipalType() {
        return this.principalType;
    }
}
