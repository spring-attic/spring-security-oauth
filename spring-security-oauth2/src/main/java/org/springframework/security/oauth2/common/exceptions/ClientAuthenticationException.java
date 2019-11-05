package org.springframework.security.oauth2.common.exceptions;

/**
 * Base exception
 *
 * <p>
 * @deprecated See the <a href="https://github.com/spring-projects/spring-security/wiki/OAuth-2.0-Migration-Guide">OAuth 2.0 Migration Guide</a> for Spring Security 5.
 *
 * @author Ryan Heaton
 * @author Dave Syer
 */
@SuppressWarnings("serial")
@Deprecated
public abstract class ClientAuthenticationException extends OAuth2Exception {

	public ClientAuthenticationException(String msg, Throwable t) {
		super(msg, t);
	}

	public ClientAuthenticationException(String msg) {
		super(msg);
	}

	@Override
	public int getHttpErrorCode() {
		// The spec says this is a bad request (not unauthorized)
		return 400;
	}

	@Override
	public abstract String getOAuth2ErrorCode();
}
