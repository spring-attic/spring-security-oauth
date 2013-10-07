package org.springframework.security.oauth2.common.exceptions;

import java.util.Set;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.common.util.OAuth2Utils;

/**
 * Exception representing insufficient scope in a token when a request is handled by a Resource Server. It is akin to an
 * {@link AccessDeniedException} and should result in a 403 (FORBIDDEN) HTTP status.
 * 
 * @author Dave Syer
 */
@SuppressWarnings("serial")
public class InsufficientScopeException extends OAuth2Exception {

	public InsufficientScopeException(String msg, Set<String> validScope) {
		this(msg);
		addAdditionalInformation("scope", OAuth2Utils.formatParameterList(validScope));
	}

	public InsufficientScopeException(String msg) {
		super(msg);
	}

	@Override
	public int getHttpErrorCode() {
		return 403;
	}

	@Override
	public String getOAuth2ErrorCode() {
		// Not defined in the spec, so not really an OAuth2Exception
		return "insufficient_scope";
	}

}