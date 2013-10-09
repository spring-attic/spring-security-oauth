package org.springframework.security.oauth2.provider;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;

import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.endpoint.AuthorizationEndpoint;
import org.springframework.security.oauth2.provider.endpoint.TokenEndpoint;

/**
 * Represents an OAuth2 token request, made at the {@link TokenEndpoint}. The requestParameters map should
 * contain the original, unmodified parameters from the original OAuth2 request.
 * 
 * In the implicit flow, a token is requested through the {@link AuthorizationEndpoint} directly, and in
 * that case the {@link AuthorizationRequest} is converted into a {@link TokenRequest} for processing
 * through the token granting chain. 
 * 
 * @author Amanda Anganes
 *
 */
@SuppressWarnings("serial")
public class TokenRequest extends BaseRequest {
	
	private String grantType;
	
	/**
	 * Default constructor
	 */
	protected TokenRequest() {
	}
	
	/**
	 * Full constructor. Sets this TokenRequest's requestParameters map to an unmodifiable version of the one provided.
	 * 
	 * @param requestParameters
	 * @param clientId
	 * @param scope
	 * @param grantType
	 */
	public TokenRequest(Map<String, String> requestParameters, String clientId, Collection<String> scope, String grantType) {
		this.clientId = clientId;
		setRequestParameters(requestParameters);
		setScope(scope);
		this.grantType = grantType;
	}

	public String getGrantType() {
		return grantType;
	}

	public void setGrantType(String grantType) {
		this.grantType = grantType;
	}

	public void setClientId(String clientId) {
		this.clientId = clientId;
	}


	/**
	 * Set the scope value. If the collection contains only a single scope
	 * value, this method will parse that value into a collection using
	 * {@link OAuth2Utils.parseParameterList}.
	 * 
	 * @param scope
	 */
	public void setScope(Collection<String> scope) {
		if (scope != null && scope.size() == 1) {
			String value = scope.iterator().next();
			/*
			 * This is really an error, but it can catch out unsuspecting users and it's easy to fix. It happens when an
			 * AuthorizationRequest gets bound accidentally from request parameters using @ModelAttribute.
			 */
			if (value.contains(" ") || value.contains(",")) {
				scope = OAuth2Utils.parseParameterList(value);
			}
		}
		this.scope = Collections.unmodifiableSet(scope == null ? new LinkedHashSet<String>()
				: new LinkedHashSet<String>(scope));
	}

	/**
	 * Set the Request Parameters on this authorization request, which represent
	 * the original request parameters and should never be changed during
	 * processing. The map passed in is wrapped in an unmodifiable map instance.
	 * 
	 * @param requestParameters
	 */
	public void setRequestParameters(Map<String, String> requestParameters) {
		if (requestParameters != null) {
			this.requestParameters = Collections.unmodifiableMap(requestParameters);
		}
	}

	public OAuth2Request createOAuth2Request(ClientDetails client) {
		// Remove password if present to prevent leaks 
		Map<String,String> requestParameters = getRequestParameters();
		HashMap<String, String> modifiable = new HashMap<String, String>(requestParameters);
		modifiable.remove("password");
		return new OAuth2Request(modifiable, client.getClientId(), client.getAuthorities(), true, this.getScope(), null, null, null, null);
	}
	
}
