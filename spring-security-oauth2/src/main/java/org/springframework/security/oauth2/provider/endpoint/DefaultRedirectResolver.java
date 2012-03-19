package org.springframework.security.oauth2.provider.endpoint;

import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.common.exceptions.RedirectMismatchException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.util.Set;

/**
 * Default implementation for a redirect resolver.
 *
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class DefaultRedirectResolver implements RedirectResolver {

	public String resolveRedirect(String requestedRedirect, ClientDetails client) throws OAuth2Exception {
		Set<String> redirectUris = client.getRegisteredRedirectUri();

		if (redirectUris != null && !redirectUris.isEmpty() && StringUtils.hasText(requestedRedirect)) {
			return obtainMatchingRedirect(redirectUris, requestedRedirect);
		}
		else if (StringUtils.hasText(requestedRedirect)) {
			return requestedRedirect;
		}
		else {
			throw new OAuth2Exception("A redirect_uri must be supplied.");
		}

	}

	/**
	 * Whether the requested redirect URI "matches" the specified redirect URI. This implementation tests if the user
	 * requrested redirect starts with the registered redirect, so it would have the same host and root path if it is an
	 * HTTP URL.
	 *
	 * @param requestedRedirect The requested redirect URI.
	 * @param redirectUri	   The registered redirect URI.
	 * @return Whether the requested redirect URI "matches" the specified redirect URI.
	 */
	protected boolean redirectMatches(String requestedRedirect, String redirectUri) {
		return requestedRedirect.startsWith(redirectUri);
	}

	/**
	 * Attempt to match one of the registered URIs to the that of the requested one.
	 *
	 * @param redirectUris	  the set of the registered URIs to try and find a match. This cannot be null or empty.
	 * @param requestedRedirect the URI used as part of the request
	 * @return the matching URI
	 * @throws RedirectMismatchException if no match was found
	 */
	private String obtainMatchingRedirect(Set<String> redirectUris, String requestedRedirect) {
		Assert.notEmpty(redirectUris, "Redirect URIs cannot be empty");
		Assert.hasText(requestedRedirect, "Requested redirect must have a value");

		for (String redirectUri : redirectUris) {
			if (redirectMatches(requestedRedirect, redirectUri)) {
				return requestedRedirect;
			}
		}
		throw new RedirectMismatchException("Invalid redirect: "
													+ requestedRedirect
													+ " does not match one of the registered values: "
													+ redirectUris.toString());
	}
}
