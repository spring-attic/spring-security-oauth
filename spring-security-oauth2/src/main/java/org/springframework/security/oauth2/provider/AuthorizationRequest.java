package org.springframework.security.oauth2.provider;

import java.io.Serializable;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.springframework.security.core.GrantedAuthority;

/**
 * Base class representing an OAuth2 Authorization Request. HTTP request parameters are stored in
 * the parameters map, and any processing the server makes throughout the lifecycle of a request are stored
 * on individual properties. The original request parameters will remain available through the parameters
 * map. For convenience, constants are defined in order to get at those original values. However, the
 * parameters map is unmodifiable so that processing cannot drop the original values.
 * 
 * @author Ryan Heaton
 * @author Dave Syer
 * @author Amanda Anganes
 */
public class AuthorizationRequest extends OAuth2Request implements Serializable {

	private static final long serialVersionUID = 1L;
	
	/**
	 * Map to hold the original, unchanged parameter set returned from the
	 * Approval Endpoint. Once set this should not be modified.
	 */
	private Map<String, String> approvalParameters = Collections.unmodifiableMap(new HashMap<String, String>());

	/**
	 * The value of the "state" parameter sent by the client in the request, if
	 * sent by the client. As this must be echoed back to the client unchanged,
	 * it should not be modified by any processing classes.
	 */
	private String state;

	/**
	 * Resolved requested response types initialized (by the
	 * OAuth2RequestFactory) with the response types originally requested.
	 */
	private Set<String> responseTypes = new HashSet<String>();

	/**
	 * Default constructor. 
	 */
	public AuthorizationRequest() {
	}
	
	/**
	 * Full constructor.
	 */
	public AuthorizationRequest(Map<String, String> authorizationParameters, Map<String, String> approvalParameters, 
			String clientId, Set<String> scope, Set<String> resourceIds, 
			Collection<? extends GrantedAuthority> authorities, boolean approved, String state, 
			String redirectUri, Set<String> responseTypes){
		super(authorizationParameters, clientId, authorities, approved, scope, resourceIds, redirectUri, null);
		if (responseTypes != null) {
			this.responseTypes = responseTypes;
		}
		this.state = state;
	}
	
	public OAuth2Request createOAuth2Request() {
		return new OAuth2Request((OAuth2Request)this);
	}

	/**
	 * Convenience constructor for unit tests, where client ID and scope are often
	 * the only needed fields.
	 * 
	 * @param clientId
	 * @param scopes
	 */
	public AuthorizationRequest(String clientId, Collection<String> scopes) {
		super(clientId);
		setScope(new HashSet<String>(scopes));
	}
	
	/**
	 * Convenience method to set resourceIds and authorities on this request by
	 * inheriting from a ClientDetails object.
	 * 
	 * @param clientDetails
	 */
	public void setResourceIdsAndAuthoritiesFromClientDetails(ClientDetails clientDetails) {
		setResourceIds(clientDetails.getResourceIds());
		setAuthorities(clientDetails.getAuthorities());
	}
	
	public Map<String, String> getApprovalParameters() {
		return approvalParameters;
	}

	public void setApprovalParameters(Map<String, String> approvalParameters) {
		this.approvalParameters = approvalParameters;
	}

	public String getState() {
		return state;
	}

	public void setState(String state) {
		this.state = state;
	}

	public Set<String> getResponseTypes() {
		return responseTypes;
	}

	public void setResponseTypes(Set<String> responseTypes) {
		this.responseTypes = responseTypes;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + ((approvalParameters == null) ? 0 : approvalParameters.hashCode());
		result = prime * result + ((responseTypes == null) ? 0 : responseTypes.hashCode());
		result = prime * result + ((state == null) ? 0 : state.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (!super.equals(obj))
			return false;
		if (getClass() != obj.getClass())
			return false;
		AuthorizationRequest other = (AuthorizationRequest) obj;
		if (approvalParameters == null) {
			if (other.approvalParameters != null)
				return false;
		}
		else if (!approvalParameters.equals(other.approvalParameters))
			return false;
		if (responseTypes == null) {
			if (other.responseTypes != null)
				return false;
		}
		else if (!responseTypes.equals(other.responseTypes))
			return false;
		if (state == null) {
			if (other.state != null)
				return false;
		}
		else if (!state.equals(other.state))
			return false;
		return true;
	}

	

}