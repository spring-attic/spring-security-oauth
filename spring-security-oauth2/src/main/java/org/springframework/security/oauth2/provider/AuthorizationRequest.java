package org.springframework.security.oauth2.provider;

import java.io.Serializable;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.common.util.OAuth2Utils;

/**
 * Base class representing a request for authorization. There are convenience methods for the well-known properties
 * required by the OAUth2 spec, and a set of generic authorizationParameters to allow for extensions.
 * 
 * 
 * Recommended usage:
 * The authorizationParameters map should contain the original request parameters sent in the HTTP request. 
 * These should not be changed during request processing. Instead, any changes should be saved in the 
 * individual parameters on this class. This way, the original request is preserved.
 * 
 * @author Ryan Heaton
 * @author Dave Syer
 * @author Amanda Anganes
 */
//TODO: This class may be poorly named
//TODO: change comments on fields to javadoc-style comments
public class AuthorizationRequest implements Serializable {

	private static final long serialVersionUID = 1L;

	public static final String CLIENT_ID = "client_id";

	public static final String STATE = "state";

	public static final String SCOPE = "scope";

	public static final String REDIRECT_URI = "redirect_uri";

	public static final String RESPONSE_TYPE = "response_type";

	public static final String USER_OAUTH_APPROVAL = "user_oauth_approval";
	
	//Represents the original, unchanged authorization parameters. Once set this should
	//not be changed.
	//expand, detail - for each param, explain when it is expected to be set, when it might change,
	//and when if at all it is expected to be frozen
	private Map<String, String> authorizationParameters = new HashMap<String, String>();
	
	//Parameters returned from the approval page are stored here. Once set this should
	//not be changed.
	private Map<String, String> approvalParameters = new HashMap<String, String>();
	
	//Client ID. 
	private String clientId;
	
	//Resolved scope. This may change as the request is processed - scopes originally
	//requested may not all be granted.
	private Set<String> scope = new HashSet<String>();

	//The resource IDs; may change during processing.
	private Set<String> resourceIds = new HashSet<String>();
	
	//The authorities that have been granted to this request. May change during
	//processing.
	private Collection<GrantedAuthority> authorities  = new HashSet<GrantedAuthority>();
	
	//Whether the request has been approved or not. This may be altered by the 
	//user approval endpoint and/or by the user approval handler.
	private boolean approved = false;
	
	//The state of the request. May change during processing.
	private String state;
	
	//The resolved redirect URI. A URI may be present in the original 
	//request, in the authorizationParameters, or it may not be provided in which 
	//case it will be defaulted to the Client's default registered value.
	private String resolvedRedirectUri;
	
	//Requested response types. 
	private Set<String> responseTypes  = new HashSet<String>();
		
	/**
	 * Default constructor. 
	 */
	public AuthorizationRequest() {
		
	}
	
	/**
	 * Full constructor.
	 * 
	 * @param authorizationParameters
	 * @param approvalParameters
	 * @param clientId
	 * @param scope
	 * @param resourceIds
	 * @param authorities
	 * @param approved
	 * @param state
	 * @param redirectUri
	 * @param responseTypes
	 */
	public AuthorizationRequest(Map<String, String> authorizationParameters, Map<String, String> approvalParameters, 
			String clientId, Set<String> scope, Set<String> resourceIds, 
			Collection<? extends GrantedAuthority> authorities, boolean approved, String state, 
			String redirectUri, Set<String> responseTypes){
		if (authorizationParameters != null) {
			this.authorizationParameters.putAll(authorizationParameters);
		}
		if (approvalParameters != null) {
			this.approvalParameters.putAll(approvalParameters);
		}
		if (resourceIds != null) {
			this.resourceIds = new HashSet<String>(resourceIds);
		}
		if (scope != null) {
			this.scope = new LinkedHashSet<String>(scope);
		}
		if (authorities != null) {
			this.authorities = new HashSet<GrantedAuthority>(authorities);
		}
		if (responseTypes != null) {
			this.responseTypes = responseTypes;
		}
		this.resolvedRedirectUri = redirectUri;
		this.state = state;
		this.clientId = clientId;
		this.approved = approved;
	}
	
	/**
	 * Convenience constructor for unit tests, where client ID and scope are often
	 * the only needed fields.
	 * 
	 * @param clientId
	 * @param scopes
	 */
	public AuthorizationRequest(String clientId, Collection<String> scopes) {
		this.clientId = clientId;
		if (scopes!= null) {
			this.scope.addAll(scopes);
		}
	}
	
	/**
	 * Convenience method to set resourceIds and authorities on this request by
	 * inheriting from a ClientDetails object.
	 * 
	 * @param clientDetails
	 */
	public void setResourceIdsAndAuthoritiesFromClientDetails(ClientDetails clientDetails) {
		resourceIds.addAll(clientDetails.getResourceIds());
		authorities.addAll(clientDetails.getAuthorities());
	}
	
	public Map<String, String> getAuthorizationParameters() {
		return authorizationParameters;
	}

	public void setAuthorizationParameters(
			Map<String, String> authorizationParameters) {
		this.authorizationParameters = authorizationParameters;
	}

	public Map<String, String> getApprovalParameters() {
		return approvalParameters;
	}

	public void setApprovalParameters(Map<String, String> approvalParameters) {
		this.approvalParameters = approvalParameters;
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

	//TODO: remove parser and do intensive wiretesting to see if this is really needed
	public void setScope(Set<String> scope) {
		if (scope != null && scope.size() == 1) {
			String value = scope.iterator().next();
			/*
			 * This is really an error, but it can catch out unsuspecting users and it's easy to fix. It happens when an
			 * AuthorizationRequest gets bound accidentally from request parameters using @ModelAttribute.
			 */
			if (value.contains(" ") || scope.contains(",")) {
				scope = OAuth2Utils.parseParameterList(value);
			}
		}
		this.scope = scope == null ? new LinkedHashSet<String>() : new LinkedHashSet<String>(scope);
	}

	public Set<String> getResourceIds() {
		return resourceIds;
	}

	public void setResourceIds(Set<String> resourceIds) {
		this.resourceIds = resourceIds;
	}

	public Collection<? extends GrantedAuthority> getAuthorities() {
		return authorities;
	}

	public void setAuthorities(Collection<? extends GrantedAuthority> authorities) {
		if (authorities!= null) {
			this.authorities = new HashSet<GrantedAuthority>(authorities);
		}
	}

	public boolean isApproved() {
		return approved;
	}

	public void setApproved(boolean approved) {
		this.approved = approved;
	}

	public String getState() {
		return state;
	}

	public void setState(String state) {
		this.state = state;
	}

	public String getRedirectUri() {
		return resolvedRedirectUri;
	}

	public void setRedirectUri(String redirectUri) {
		this.resolvedRedirectUri = redirectUri;
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
		int result = 1;
		result = prime
				* result
				+ ((approvalParameters == null) ? 0 : approvalParameters
						.hashCode());
		result = prime * result + (approved ? 1231 : 1237);
		result = prime * result
				+ ((authorities == null) ? 0 : authorities.hashCode());
		result = prime
				* result
				+ ((authorizationParameters == null) ? 0
						: authorizationParameters.hashCode());
		result = prime * result
				+ ((clientId == null) ? 0 : clientId.hashCode());
		result = prime
				* result
				+ ((resolvedRedirectUri == null) ? 0 : resolvedRedirectUri
						.hashCode());
		result = prime * result
				+ ((resourceIds == null) ? 0 : resourceIds.hashCode());
		result = prime * result
				+ ((responseTypes == null) ? 0 : responseTypes.hashCode());
		result = prime * result + ((scope == null) ? 0 : scope.hashCode());
		result = prime * result + ((state == null) ? 0 : state.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (!(obj instanceof AuthorizationRequest)) {
			return false;
		}
		AuthorizationRequest other = (AuthorizationRequest) obj;
		if (approvalParameters == null) {
			if (other.approvalParameters != null) {
				return false;
			}
		} else if (!approvalParameters.equals(other.approvalParameters)) {
			return false;
		}
		if (approved != other.approved) {
			return false;
		}
		if (authorities == null) {
			if (other.authorities != null) {
				return false;
			}
		} else if (!authorities.equals(other.authorities)) {
			return false;
		}
		if (authorizationParameters == null) {
			if (other.authorizationParameters != null) {
				return false;
			}
		} else if (!authorizationParameters
				.equals(other.authorizationParameters)) {
			return false;
		}
		if (clientId == null) {
			if (other.clientId != null) {
				return false;
			}
		} else if (!clientId.equals(other.clientId)) {
			return false;
		}
		if (resolvedRedirectUri == null) {
			if (other.resolvedRedirectUri != null) {
				return false;
			}
		} else if (!resolvedRedirectUri.equals(other.resolvedRedirectUri)) {
			return false;
		}
		if (resourceIds == null) {
			if (other.resourceIds != null) {
				return false;
			}
		} else if (!resourceIds.equals(other.resourceIds)) {
			return false;
		}
		if (responseTypes == null) {
			if (other.responseTypes != null) {
				return false;
			}
		} else if (!responseTypes.equals(other.responseTypes)) {
			return false;
		}
		if (scope == null) {
			if (other.scope != null) {
				return false;
			}
		} else if (!scope.equals(other.scope)) {
			return false;
		}
		if (state == null) {
			if (other.state != null) {
				return false;
			}
		} else if (!state.equals(other.state)) {
			return false;
		}
		return true;
	}

}