package org.springframework.security.oauth2.provider;

import java.io.Serializable;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.common.util.OAuth2Utils;

/**
 * Base class representing an OAuth2 authorization or token request. HTTP request parameters are stored in
 * the parameters map, and any processing the server makes throughout the lifecycle of a request are stored
 * on individual properties. The original request parameters will remain available through the parameters
 * map, so for convenience constants are defined in order to get at those original values. However, the
 * parameters map is unmodifiable so that processing cannot drop the original values.
 * 
 * @author Ryan Heaton
 * @author Dave Syer
 * @author Amanda Anganes
 */
public class OAuth2Request implements Serializable {

	private static final long serialVersionUID = 1L;

	public static final String CLIENT_ID = "client_id";

	public static final String STATE = "state";

	public static final String SCOPE = "scope";

	public static final String REDIRECT_URI = "redirect_uri";

	public static final String RESPONSE_TYPE = "response_type";

	public static final String USER_OAUTH_APPROVAL = "user_oauth_approval";
	
	/**
	 * Original, unchanged request parameters. In order to preserve the original request, this map 
	 * should not be modified after initialization.
	 * 
	 * The OAuth2RequestFactory is responsible for populating the individual members, defined below,
	 * with sensible initialized values. In general processing classes should not retrieve values
	 * from this map directly, and should instead use the individual members on this class.
	 */
	private Map<String, String> requestParameters = Collections.unmodifiableMap(new HashMap<String, String>());
	
	/**
	 * Map to hold the original, unchanged parameter set returned from the Approval Endpoint. 
	 * Once set this should not be modified. 
	 */
	private Map<String, String> approvalParameters = Collections.unmodifiableMap(new HashMap<String, String>());
	
	/**
	 * Resolved client ID. This may be present in the original request parameters, or in some cases
	 * may be inferred by a processing class and inserted here.
	 */
	private String clientId;
	
	/**
	 * Resolved scope set, initialize with the scopes originally requested. Further processing and 
	 * user interaction may alter the set of scopes that is finally granted and stored when the request 
	 * processing is complete.
	 */
	private Set<String> scope = new HashSet<String>();

	/**
	 * Resolved resource IDs. This set may change during request processing.
	 */
	private Set<String> resourceIds = new HashSet<String>();
	
	/**
	 * Resolved granted authorities for this request. May change during request processing.
	 */
	private Collection<GrantedAuthority> authorities  = new HashSet<GrantedAuthority>();
	
	/**
	 * Whether the request has been approved or not. This may be altered by the User Approval 
	 * Endpoint and/or the UserApprovalHandler.
	 */
	private boolean approved = false;
	
	/**
	 * The state of the request, if sent by the client. This must be echoed back to the 
	 * client unchanged, so it should not be modified by any processing classes.
	 */
	private String state;
	
	/**
	 * The resolved redirect URI of this request. A URImay be present in the original request, 
	 * in the authorizationParameters, or it may not be provided, in which case it will
	 * be defaulted (by processing classes) to the Client's default registered value.
	 */
	private String resolvedRedirectUri;
	
	/**
	 * Resolved requested response types. 
	 */
	private Set<String> responseTypes  = new HashSet<String>();
	
	/**
	 * Extension point for custom processing classes which may wish to store additional 
	 * information about the OAuth2 request.
	 */
	private Map<String, Serializable> extensionProperties = new HashMap<String, Serializable>();
		
	/**
	 * Default constructor. 
	 */
	public OAuth2Request() {
		
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
	public OAuth2Request(Map<String, String> authorizationParameters, Map<String, String> approvalParameters, 
			String clientId, Set<String> scope, Set<String> resourceIds, 
			Collection<? extends GrantedAuthority> authorities, boolean approved, String state, 
			String redirectUri, Set<String> responseTypes){
		if (authorizationParameters != null) {
			//this.authorizationParameters.putAll(authorizationParameters);
			this.requestParameters = Collections.unmodifiableMap(authorizationParameters);
		}
		if (approvalParameters != null) {
			this.approvalParameters = Collections.unmodifiableMap(approvalParameters);
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
	public OAuth2Request(String clientId, Collection<String> scopes) {
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
	
	/**
	 * Warning: most classes should use the individual properties of this class, such 
	 * as clientId or scope, rather than retrieving values from this map.
	 * @return the original, unchanged set of request parameters
	 */
	public Map<String, String> getRequestParameters() {
		return requestParameters;
	}

	/**
	 * Warning: most classes should not alter this map after it has been initialized.
	 * @param requestParameters the original, unchanged set of request parameters to set
	 */
	public void setRequestParameters(
			Map<String, String> requestParameters) {
		this.requestParameters = Collections.unmodifiableMap(requestParameters);
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

	/**
	 * @return the extensionProperties
	 */
	public Map<String, Serializable> getExtensionProperties() {
		return extensionProperties;
	}

	/**
	 * @param extensionProperties the extensionProperties to set
	 */
	public void setExtensionProperties(Map<String, Serializable> extensionProperties) {
		this.extensionProperties = extensionProperties;
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
				+ ((requestParameters == null) ? 0
						: requestParameters.hashCode());
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
		if (!(obj instanceof OAuth2Request)) {
			return false;
		}
		OAuth2Request other = (OAuth2Request) obj;
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
		if (requestParameters == null) {
			if (other.requestParameters != null) {
				return false;
			}
		} else if (!requestParameters
				.equals(other.requestParameters)) {
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