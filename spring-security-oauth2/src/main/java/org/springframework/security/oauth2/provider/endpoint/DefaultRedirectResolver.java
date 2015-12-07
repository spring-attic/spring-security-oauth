/*
 * Copyright 2002-2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.provider.endpoint;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.common.exceptions.RedirectMismatchException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * Default implementation for a redirect resolver.
 * 
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class DefaultRedirectResolver implements RedirectResolver {

	private Collection<String> redirectGrantTypes = Arrays.asList("implicit", "authorization_code");

	private boolean matchSubdomains = true;

	/**
	 * Flag to indicate that requested URIs will match if they are a subdomain of the registered value.
	 * 
	 * @param matchSubdomains the flag value to set (deafult true)
	 */
	public void setMatchSubdomains(boolean matchSubdomains) {
		this.matchSubdomains = matchSubdomains;
	}

	/**
	 * Grant types that are permitted to have a redirect uri.
	 * 
	 * @param redirectGrantTypes the redirect grant types to set
	 */
	public void setRedirectGrantTypes(Collection<String> redirectGrantTypes) {
		this.redirectGrantTypes = new HashSet<String>(redirectGrantTypes);
	}

	public String resolveRedirect(String requestedRedirect, ClientDetails client) throws OAuth2Exception {

		Set<String> authorizedGrantTypes = client.getAuthorizedGrantTypes();
		if (authorizedGrantTypes.isEmpty()) {
			throw new InvalidGrantException("A client must have at least one authorized grant type.");
		}
		if (!containsRedirectGrantType(authorizedGrantTypes)) {
			throw new InvalidGrantException(
					"A redirect_uri can only be used by implicit or authorization_code grant types.");
		}

		Set<String> redirectUris = client.getRegisteredRedirectUri();

		if (redirectUris != null && !redirectUris.isEmpty()) {
			return obtainMatchingRedirect(redirectUris, requestedRedirect);
		}
		else if (StringUtils.hasText(requestedRedirect)) {
			return requestedRedirect;
		}
		else {
			throw new InvalidRequestException("A redirect_uri must be supplied.");
		}

	}

	/**
	 * @param grantTypes some grant types
	 * @return true if the supplied grant types includes one or more of the redirect types
	 */
	private boolean containsRedirectGrantType(Set<String> grantTypes) {
		for (String type : grantTypes) {
			if (redirectGrantTypes.contains(type)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Whether the requested redirect URI "matches" the specified redirect URI. For a URL, this implementation tests if
	 * the user requested redirect starts with the registered redirect, so it would have the same host and root path if
	 * it is an HTTP URL. The port is not matched.
	 * <p>
	 * For other (non-URL) cases, such as for some implicit clients, the redirect_uri must be an exact match.
	 * 
	 * @param requestedRedirect The requested redirect URI.
	 * @param redirectUri The registered redirect URI.
	 * @return Whether the requested redirect URI "matches" the specified redirect URI.
	 */
	protected boolean redirectMatches(String requestedRedirect, String redirectUri) {
		try {
			URL req = new URL(requestedRedirect);
			URL reg = new URL(redirectUri);

			if (reg.getProtocol().equals(req.getProtocol()) && hostMatches(reg.getHost(), req.getHost())) {
				return StringUtils.cleanPath(req.getPath()).startsWith(StringUtils.cleanPath(reg.getPath()));
			}
		}
		catch (MalformedURLException e) {
		}
		return requestedRedirect.equals(redirectUri);
	}

	/**
	 * Check if host matches the registered value.
	 * 
	 * @param registered the registered host
	 * @param requested the requested host
	 * @return true if they match
	 */
	protected boolean hostMatches(String registered, String requested) {
		if (matchSubdomains) {
			return requested.endsWith(registered);
		}
		return registered.equals(requested);
	}

	/**
	 * Attempt to match one of the registered URIs to the that of the requested one.
	 * 
	 * @param redirectUris the set of the registered URIs to try and find a match. This cannot be null or empty.
	 * @param requestedRedirect the URI used as part of the request
	 * @return the matching URI
	 * @throws RedirectMismatchException if no match was found
	 */
	private String obtainMatchingRedirect(Set<String> redirectUris, String requestedRedirect) {
		Assert.notEmpty(redirectUris, "Redirect URIs cannot be empty");

		if (redirectUris.size() == 1 && requestedRedirect == null) {
			return redirectUris.iterator().next();
		}
		for (String redirectUri : redirectUris) {
			if (requestedRedirect != null && redirectMatches(requestedRedirect, redirectUri)) {
				return requestedRedirect;
			}
		}
		throw new RedirectMismatchException("Invalid redirect: " + requestedRedirect
				+ " does not match one of the registered values: " + redirectUris.toString());
	}
}
