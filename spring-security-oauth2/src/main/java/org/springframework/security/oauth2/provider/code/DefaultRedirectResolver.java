package org.springframework.security.oauth2.provider.code;

import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.common.exceptions.RedirectMismatchException;
import org.springframework.security.oauth2.provider.ClientDetails;

/**
 * Default implementation for a redirect resolver.
 * 
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class DefaultRedirectResolver implements RedirectResolver {

	public String resolveRedirect(String requestedRedirect, ClientDetails client) throws OAuth2Exception {

		String redirectUri = client.getRegisteredRedirectUri();

		if (redirectUri != null && requestedRedirect != null) {
			if (!redirectMatches(requestedRedirect, redirectUri)) {
				throw new RedirectMismatchException("Invalid redirect: " + requestedRedirect
						+ " does not match registered value: " + redirectUri);
			}
			else {
				redirectUri = requestedRedirect;
			}
		}

		if (redirectUri == null) {
			if (requestedRedirect == null) {
				throw new OAuth2Exception("A redirect_uri must be supplied.");
			}
			redirectUri = requestedRedirect;
		}

		return redirectUri;

	}

	/**
	 * Whether the requested redirect URI "matches" the specified redirect URI. This implementation tests if the user
	 * requrested redirect starts with the registered redirect, so it would have the same host and root path if it is an
	 * HTTP URL.
	 * 
	 * @param requestedRedirect The requested redirect URI.
	 * @param redirectUri The registered redirect URI.
	 * @return Whether the requested redirect URI "matches" the specified redirect URI.
	 */
	protected boolean redirectMatches(String requestedRedirect, String redirectUri) {
		return requestedRedirect.startsWith(redirectUri);
	}
}
