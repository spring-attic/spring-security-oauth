package org.springframework.security.oauth2.client.resource;

import java.util.Map;

/**
 * Special exception thrown when a user redirect is required in order to obtain an OAuth2 access token.
 * 
 * @author Ryan Heaton
 */
@SuppressWarnings("serial")
public class UserRedirectRequiredException extends RuntimeException {

	private final String redirectUri;

	private final Map<String, String> requestParams;

	private String stateKey;

	private Object stateToPreserve;

	public UserRedirectRequiredException(String redirectUri, Map<String, String> requestParams) {
		super("A redirect is required to get the users approval");
		this.redirectUri = redirectUri;
		this.requestParams = requestParams;
	}

	/**
	 * The uri to which the user is to be redirected.
	 * 
	 * @return The uri to which the user is to be redirected.
	 */
	public String getRedirectUri() {
		return redirectUri;
	}

	/**
	 * The request parameters that are to be appended to the uri.
	 * 
	 * @return The request parameters that are to be appended to the uri.
	 */
	public Map<String, String> getRequestParams() {
		return requestParams;
	}

	/**
	 * The key to the state to preserve.
	 * 
	 * @return The key to the state to preserve.
	 */
	public String getStateKey() {
		return stateKey;
	}

	/**
	 * The key to the state to preserve.
	 * 
	 * @param stateKey The key to the state to preserve.
	 */
	public void setStateKey(String stateKey) {
		this.stateKey = stateKey;
	}

	/**
	 * Some state that needs to be preserved and set up in the security context when the user returns.
	 * 
	 * @return The state that needs to be preserved.
	 */
	public Object getStateToPreserve() {
		return stateToPreserve;
	}

	/**
	 * The state that needs to be preserved and set up in the security context when the user returns.
	 * 
	 * @param stateToPreserve The state.
	 */
	public void setStateToPreserve(Object stateToPreserve) {
		this.stateToPreserve = stateToPreserve;
	}
}
