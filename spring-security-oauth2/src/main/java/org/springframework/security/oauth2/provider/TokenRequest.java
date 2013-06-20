package org.springframework.security.oauth2.provider;

import java.util.Collections;
import java.util.Map;
import java.util.Set;

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
public class TokenRequest {

	private Map<String, String> requestParameters;
	private String clientId;
	private Set<String> scope;
	private String grantType;
	
	/**
	 * Full constructor. Sets this TokenRequest's requestParameters map to an unmodifiable version of the one provided.
	 * 
	 * @param requestParameters
	 * @param clientId
	 * @param scope
	 * @param grantType
	 */
	public TokenRequest(Map<String, String> requestParameters, String clientId, Set<String> scope, String grantType) {
		
		if (requestParameters != null) {
			this.requestParameters = Collections.unmodifiableMap(requestParameters);
		}
		
		this.clientId = clientId;
		this.scope = scope;
		this.grantType = grantType;
	}

	/**
	 * Warning: most classes should not need to interact with the parameters map directly.
	 * 
	 * @return the original token request's parameters map
	 */
	public Map<String, String> getRequestParameters() {
		return requestParameters;
	}

	/**
	 * Warning: This method should not be called during normal usage. Instead, properties that need to be
	 * altered during processing should be stored on individual property fields on this object.
	 * 
	 * @param requestParameters the parameter map to set
	 */
	public void setRequestParameters(Map<String, String> requestParameters) {
		this.requestParameters = requestParameters;
	}

	public String getClientId() {
		return clientId;
	}

	public void setClientId(String clientId) {
		this.clientId = clientId;
	}

	public Set<String> getScope() {
		return scope;
	}

	public void setScope(Set<String> scope) {
		this.scope = scope;
	}

	public String getGrantType() {
		return grantType;
	}

	public void setGrantType(String grantType) {
		this.grantType = grantType;
	}
	
}
