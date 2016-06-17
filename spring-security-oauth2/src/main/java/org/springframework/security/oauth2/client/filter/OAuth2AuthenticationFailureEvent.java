package org.springframework.security.oauth2.client.filter;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.core.AuthenticationException;

@SuppressWarnings("serial")
public class OAuth2AuthenticationFailureEvent extends AbstractAuthenticationFailureEvent {

	public OAuth2AuthenticationFailureEvent(AuthenticationException exception) {
		super(new FailedOAuthClientAuthentication(), exception);
	}

}

@SuppressWarnings("serial")
class FailedOAuthClientAuthentication extends AbstractAuthenticationToken {

	public FailedOAuthClientAuthentication() {
		super(null);
	}

	@Override
	public Object getCredentials() {
		return "";
	}

	@Override
	public Object getPrincipal() {
		return "UNKNOWN";
	}
	
}