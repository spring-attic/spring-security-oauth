package org.springframework.security.oauth2.provider.code;

import org.springframework.security.oauth2.provider.ClientAuthenticationToken;

import java.util.Set;

/**
 * Authentication token for a request for authorization of an as-yet-unconfirmed authorization code.
 * 
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class AuthorizationCodeAuthenticationToken extends ClientAuthenticationToken {

	private final String authorizationCode;
	private final String requestedRedirect;
	private final String state;

	public AuthorizationCodeAuthenticationToken(String clientId, String clientSecret, Set<String> scope,
			String authorizationCode, String state, String requestedRedirect) {
		super(clientId, clientSecret, scope);
		this.authorizationCode = authorizationCode;
		this.state = state;
		this.requestedRedirect = requestedRedirect;
	}

	public String getAuthorizationCode() {
		return authorizationCode;
	}

	public String getRequestedRedirect() {
		return requestedRedirect;
	}
	
	public String getState() {
		return state;
	}
}