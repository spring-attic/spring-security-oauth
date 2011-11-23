package org.springframework.security.oauth2.client.filter.flash;

import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.oauth2.common.OAuth2AccessToken;

/**
 * Basic, no-op implementation of the remember-me services.
 * 
 * @author Ryan Heaton
 */
public class NoOpClientTokenFlashServices implements ClientTokenCache {

	public Map<String, OAuth2AccessToken> loadRememberedTokens(HttpServletRequest request, HttpServletResponse response) {
		return null;
	}

	public void rememberTokens(Map<String, OAuth2AccessToken> tokens, HttpServletRequest request,
			HttpServletResponse response) {
	}

}
