package org.springframework.security.oauth.consumer.rememberme;

import org.springframework.security.oauth.consumer.OAuthConsumerToken;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Map;

/**
 * Basic, no-op implementation of the remember-me services. Not very useful in a 3-legged OAuth flow, but for a 2-legged
 * system where there are no request tokens to store in between requests it keeps the consumer stateless at the price of
 * obtaining a new access token for every request.
 *
 * <p>
 * @deprecated The OAuth 1.0 Protocol <a href="https://tools.ietf.org/html/rfc5849">RFC 5849</a> is obsoleted by the OAuth 2.0 Authorization Framework <a href="https://tools.ietf.org/html/rfc6749">RFC 6749</a>.
 *
 * @author Ryan Heaton
 */
@Deprecated
public class NoOpOAuthRememberMeServices implements OAuthRememberMeServices {

	public Map<String, OAuthConsumerToken> loadRememberedTokens(HttpServletRequest request, HttpServletResponse response) {
		return null;
	}

	public void rememberTokens(Map<String, OAuthConsumerToken> tokens, HttpServletRequest request,
			HttpServletResponse response) {
	}

}
