package org.springframework.security.oauth2.client.filter;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.core.AuthenticationException;

/**
 * <p>
 * @deprecated See the <a href="https://github.com/spring-projects/spring-security/wiki/OAuth-2.0-Migration-Guide">OAuth 2.0 Migration Guide</a> for Spring Security 5.
 *
 */
@SuppressWarnings("serial")
@Deprecated
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