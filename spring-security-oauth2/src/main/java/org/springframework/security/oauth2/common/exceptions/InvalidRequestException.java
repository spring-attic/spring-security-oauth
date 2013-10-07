package org.springframework.security.oauth2.common.exceptions;

/**
 * @author Dave Syer
 */
@SuppressWarnings("serial")
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
