package org.springframework.security.oauth2.provider;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.endpoint.AuthorizationEndpoint;
import org.springframework.security.oauth2.provider.endpoint.TokenEndpoint;

/**
 * Represents an OAuth2 token request, made at the {@link TokenEndpoint}. The requestParameters map should contain the
 * original, unmodified parameters from the original OAuth2 request.
 * 
 * In the implicit flow, a token is requested through the {@link AuthorizationEndpoint} directly, and in that case the
 * {@link AuthorizationRequest} is converted into a {@link TokenRequest} for processing through the token granting
 * chain.
 * 
 * @author Amanda Anganes
 * @author Dave Syer
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
	public TokenRequest(Map<String, String> requestParameters, String clientId, Collection<String> scope,
			String grantType) {
		setClientId(clientId);
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
		super.setClientId(clientId);
	}

	/**
	 * Set the scope value. If the collection contains only a single scope value, this method will parse that value into
	 * a collection using {@link OAuth2Utils#parseParameterList}.
	 * 
	 * @see AuthorizationRequest#setScope
	 * 
	 * @param scope
	 */
	public void setScope(Collection<String> scope) {
		super.setScope(scope);
	}

	/**
	 * Set the Request Parameters on this authorization request, which represent the original request parameters and
	 * should never be changed during processing. The map passed in is wrapped in an unmodifiable map instance.
	 * 
	 * @see AuthorizationRequest#setRequestParameters
	 * 
	 * @param requestParameters
	 */
	public void setRequestParameters(Map<String, String> requestParameters) {
		super.setRequestParameters(requestParameters);
	}

	public OAuth2Request createOAuth2Request(ClientDetails client) {
		Map<String, String> requestParameters = getRequestParameters();
		HashMap<String, String> modifiable = new HashMap<String, String>(requestParameters);
		// Remove password if present to prevent leaks
		modifiable.remove("password");
		modifiable.remove("client_secret");
		// Add grant type so it can be retrieved from OAuth2Request
		modifiable.put("grant_type", grantType);
		return new OAuth2Request(modifiable, client.getClientId(), client.getAuthorities(), true, this.getScope(),
				client.getResourceIds(), null, null, null);
	}

}
