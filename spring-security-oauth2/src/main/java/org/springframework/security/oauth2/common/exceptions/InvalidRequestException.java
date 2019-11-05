package org.springframework.security.oauth2.common.exceptions;

/**
 * <p>
 * @deprecated See the <a href="https://github.com/spring-projects/spring-security/wiki/OAuth-2.0-Migration-Guide">OAuth 2.0 Migration Guide</a> for Spring Security 5.
 *
 * @author Dave Syer
 */
@SuppressWarnings("serial")
@Deprecated
public class InvalidRequestException extends ClientAuthenticationException {

	public InvalidRequestException(String msg, Throwable t) {
		super(msg, t);
	}

	public InvalidRequestException(String msg) {
		super(msg);
	}

	@Override
	public String getOAuth2ErrorCode() {
		return "invalid_request";
	}
}
