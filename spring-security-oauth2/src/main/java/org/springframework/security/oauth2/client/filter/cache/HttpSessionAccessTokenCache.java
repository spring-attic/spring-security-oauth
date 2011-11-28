package org.springframework.security.oauth2.client.filter.cache;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

/**
 * Default implementation of the OAuth2 rememberme services. Just stores everything in the session.
 * 
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class HttpSessionAccessTokenCache implements AccessTokenCache {

	private static final String REMEMBERED_TOKENS_KEY = HttpSessionAccessTokenCache.class.getName()
			+ "#REMEMBERED_TOKENS";

	private Map<String, OAuth2AccessToken> clientTokens = new HashMap<String, OAuth2AccessToken>();

	private boolean allowSessionCreation = true;

	/**
	 * If set to true (the default), a session will be created (if required) to store the token if it is determined that
	 * its contents are different from the default empty context value.
	 * <p>
	 * Note that setting this flag to false does not prevent this class from storing the token. If your application (or
	 * another filter) creates a session, then the token will still be stored for an authenticated user.
	 * 
	 * @param allowSessionCreation
	 */
	public void setAllowSessionCreation(boolean allowSessionCreation) {
		this.allowSessionCreation = allowSessionCreation;
	}

	public Map<String, OAuth2AccessToken> loadRememberedTokens(HttpServletRequest request, HttpServletResponse response) {
		// Ensure session is created if necessary. TODO: find a better way to do this
		HttpSession session = request.getSession(allowSessionCreation);
		Map<String, OAuth2AccessToken> tokens = new HashMap<String, OAuth2AccessToken>(clientTokens);
		if (session != null) {
			@SuppressWarnings("unchecked")
			Map<String, OAuth2AccessToken> rememberedTokens = (Map<String, OAuth2AccessToken>) session
					.getAttribute(REMEMBERED_TOKENS_KEY);
			if (rememberedTokens != null) {
				tokens.putAll(rememberedTokens);
			}
		}
		return tokens;
	}

	public void rememberTokens(Map<OAuth2ProtectedResourceDetails, OAuth2AccessToken> map, HttpServletRequest request,
			HttpServletResponse response) {
		HttpSession session = request.getSession(allowSessionCreation);
		if (session != null) {
			Map<String, OAuth2AccessToken> tokens = new HashMap<String, OAuth2AccessToken>();
			@SuppressWarnings("unchecked")
			Map<String, OAuth2AccessToken> rememberedTokens = (Map<String, OAuth2AccessToken>) session
					.getAttribute(REMEMBERED_TOKENS_KEY);
			if (rememberedTokens != null) {
				tokens.putAll(rememberedTokens);
			}
			for (OAuth2ProtectedResourceDetails resource : map.keySet()) {
				if (!resource.isClientOnly()) {
					tokens.put(resource.getId(), map.get(resource));
				}
			}
			session.setAttribute(REMEMBERED_TOKENS_KEY, Collections.unmodifiableMap(tokens));
		}
		for (OAuth2ProtectedResourceDetails resource : map.keySet()) {
			if (resource.isClientOnly()) {
				clientTokens.put(resource.getId(), map.get(resource));
			}
		}
	}

}
