package org.springframework.security.oauth2.client.resource;

import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;

/**
 * When access is denied we usually want a 403, but we want the same treatment as all the other OAuth2Exception types,
 * so this is not a Spring Security AccessDeniedException.
 *
 * <p>
 * @deprecated See the <a href="https://github.com/spring-projects/spring-security/wiki/OAuth-2.0-Migration-Guide">OAuth 2.0 Migration Guide</a> for Spring Security 5.
 *
 * @author Ryan Heaton
 * @author Dave Syer
 */
@SuppressWarnings("serial")
@Deprecated
public class OAuth2AccessDeniedException extends OAuth2Exception {

	private OAuth2ProtectedResourceDetails resource;

	public OAuth2AccessDeniedException() {
		super("OAuth2 access denied.");
	}

	public OAuth2AccessDeniedException(String msg) {
		super(msg);
	}

	public OAuth2AccessDeniedException(OAuth2ProtectedResourceDetails resource) {
		super("OAuth2 access denied.");
		this.resource = resource;
	}

	public OAuth2AccessDeniedException(String msg, OAuth2ProtectedResourceDetails resource) {
		super(msg);
		this.resource = resource;
	}

	public OAuth2AccessDeniedException(String msg, OAuth2ProtectedResourceDetails resource, Throwable t) {
		super(msg, t);
		this.resource = resource;
	}

	public OAuth2ProtectedResourceDetails getResource() {
		return resource;
	}

	public void setResource(OAuth2ProtectedResourceDetails resource) {
		this.resource = resource;
	}

	@Override
	public String getOAuth2ErrorCode() {
		return "access_denied";
	}

	@Override
	public int getHttpErrorCode() {
		return 403;
	}
}
