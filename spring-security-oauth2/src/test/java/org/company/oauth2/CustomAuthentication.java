package org.company.oauth2;

import org.springframework.security.authentication.AbstractAuthenticationToken;

public class CustomAuthentication extends AbstractAuthenticationToken  {

    private static final long serialVersionUID = 1L;

    private String principal;

    public CustomAuthentication(String name, boolean authenticated) {
        super(null);
        setAuthenticated(authenticated);
        this.principal = name;
    }

    public Object getCredentials() {
        return null;
    }

    public Object getPrincipal() {
        return this.principal;
    }
}
