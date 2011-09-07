package org.springframework.security.oauth2.provider.refresh;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.provider.AccessGrantAuthenticationToken;

import java.util.Set;
import java.util.TreeSet;

/**
 * @author Ryan Heaton
 */
public class RefreshAuthenticationToken extends AbstractAuthenticationToken {

	private final String refreshToken;
	private final Set<String> scope;
	private AccessGrantAuthenticationToken clientAuthentication;

	public RefreshAuthenticationToken(String clientId, String clientSecret, String refreshToken, Set<String> scope) {
		super(null);
		this.scope = scope;
		this.clientAuthentication = new AccessGrantAuthenticationToken(clientId, clientSecret, new TreeSet<String>(), "refresh_token");
		this.refreshToken = refreshToken;
	}

	public AccessGrantAuthenticationToken getClientAuthentication() {
		return clientAuthentication;
	}

	public String getRefreshToken() {
		return refreshToken;
	}

	public Set<String> getScope() {
		return scope;
	}

	public Object getCredentials() {
		return this.refreshToken;
	}

	public Object getPrincipal() {
		return this.clientAuthentication.getPrincipal();
	}

}
