package org.springframework.security.oauth2.provider;

import java.util.Map;
import java.util.Set;

import org.springframework.security.oauth2.common.util.OAuth2Utils;

/**
 * Client token for a request for a authorization.
 * 
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class AuthorizationRequest extends ClientToken {

	private final String state;

	private final String requestedRedirect;

	private boolean denied;

	public AuthorizationRequest(String clientId, String clientSecret, Set<String> scope, String state,
			String requestedRedirect) {
		super(clientId, clientSecret, scope);
		this.state = state;
		this.requestedRedirect = requestedRedirect;
	}

	public AuthorizationRequest(Map<String, String> parameters) {
		this(parameters.get("client_id"), null, OAuth2Utils.parseScope(parameters.get("scope")), parameters
				.get("state"), parameters.get("redirect_uri"));
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