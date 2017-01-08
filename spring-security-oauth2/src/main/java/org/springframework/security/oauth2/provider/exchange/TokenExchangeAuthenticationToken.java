package org.springframework.security.oauth2.provider.exchange;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.provider.ClientDetails;

/**
 * @author Ryan Murfitt
 */
public class TokenExchangeAuthenticationToken extends AbstractAuthenticationToken {

    private final Object principal;
    private final String principalType;
    private final ClientDetails clientDetails;

    TokenExchangeAuthenticationToken(Object principal, String principalType, ClientDetails clientDetails) {
        super(null);
        this.principal = principal;
        this.principalType = principalType;
        this.clientDetails = clientDetails;
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }

    public String getPrincipalType() {
        return principalType;
    }

    public ClientDetails getClientDetails() {
        return clientDetails;
    }
}
