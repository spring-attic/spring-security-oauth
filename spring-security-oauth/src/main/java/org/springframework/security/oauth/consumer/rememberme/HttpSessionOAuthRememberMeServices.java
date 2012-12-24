package org.springframework.security.oauth.consumer.rememberme;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.security.oauth.consumer.OAuthConsumerToken;

/**
 * Default implementation of the OAuth2 rememberme services. Just stores everything in the session by default. Storing
 * access token can be suppressed to reduce long-term expose of these tokens in the underlying HTTP session.
 * 
 * @author Ryan Heaton
 * @author Alex Rau
 */
public class HttpSessionOAuthRememberMeServices implements OAuthRememberMeServices {

	public static final String REMEMBERED_TOKENS_KEY = HttpSessionOAuthRememberMeServices.class.getName()
			+ "#REMEMBERED_TOKENS";

	private boolean storeAccessTokens = true;

	@SuppressWarnings("unchecked")
	public Map<String, OAuthConsumerToken> loadRememberedTokens(HttpServletRequest request, HttpServletResponse response) {
		
		HttpSession session = request.getSession(false);

		if (session != null) {
			return (Map<String, OAuthConsumerToken>) session.getAttribute(REMEMBERED_TOKENS_KEY);
		}
		
		return null;
	}

	public void rememberTokens(Map<String, OAuthConsumerToken> tokens, HttpServletRequest request,
			HttpServletResponse response) {

		HttpSession session = request.getSession(false);

		if (session == null) {
			return;
		}

		Map<String, OAuthConsumerToken> requestTokensOnly = new HashMap<String, OAuthConsumerToken>();

		for (Map.Entry<String, OAuthConsumerToken> token : tokens.entrySet()) {
			if (storeAccessTokens && !token.getValue().isAccessToken())
				requestTokensOnly.put(token.getKey(), token.getValue());

		}

		session.setAttribute(REMEMBERED_TOKENS_KEY, requestTokensOnly);
	}
}
