package org.springframework.security.oauth2.provider.code;

import org.springframework.security.oauth2.provider.ClientToken;

import java.util.Set;

/**
 * Client token for a request for a authorization code.
 * 
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class UnconfirmedAuthorizationCodeClientToken extends ClientToken {

	private final String state;
	private final String requestedRedirect;
	private boolean denied;

	public UnconfirmedAuthorizationCodeClientToken(String clientId, Set<String> scope, String state,
			String requestedRedirect) {
		super(clientId, null, scope);
		this.state = state;
		this.requestedRedirect = requestedRedirect;
	}

	public String getRequestedRedirect() {
		return requestedRedirect;
	}

	public String getState() {
		return state;
	}

	public boolean isDenied() {
		return denied;
	}

	// TODO: make this immutable
	public void setDenied(boolean denied) {
		this.denied = denied;
		setApproved(!denied);
	}

}