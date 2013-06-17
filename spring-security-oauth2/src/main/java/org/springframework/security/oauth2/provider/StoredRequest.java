package org.springframework.security.oauth2.provider;

import java.io.Serializable;
import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.springframework.security.core.GrantedAuthority;

/**
 * Represents a stored authorization or token request. Used as part of the OAuth2Authentication object to store
 * the client's authentication information. 
 * 
 * @author Amanda Anganes
 *
 */
public class StoredRequest implements Serializable {
	
	private static final long serialVersionUID = 1L;
	
	private String clientId;
	private Set<GrantedAuthority> authorities;
	private boolean approved;
	private Set<String> scope;
	private Set<String> resourceIds;
	private Map<String, String> requestParameters;
	
	public StoredRequest(Map<String, String> requestParameters, String clientId, Collection<? extends GrantedAuthority> authorities, boolean approved, Set<String> scope, Set<String> resourceIds) {
		this.requestParameters = requestParameters;
		this.clientId = clientId;
		this.authorities = (authorities!=null ? new HashSet<GrantedAuthority>(authorities) : null);
		this.approved = approved;
		this.scope = scope;
		this.resourceIds = resourceIds;
	}

	public String getClientId() {
		return clientId;
	}
	
	public Set<GrantedAuthority> getAuthorities() {
		return authorities;
	}
	
	public boolean isApproved() {
		return approved;
	}
	
	public Set<String> getScope() {
		return scope;
	}

	public Set<String> getResourceIds() {
		return resourceIds;
	}

	public Map<String, String> getRequestParameters() {
		return requestParameters;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + (approved ? 1231 : 1237);
		result = prime * result
				+ ((authorities == null) ? 0 : authorities.hashCode());
		result = prime * result
				+ ((clientId == null) ? 0 : clientId.hashCode());
		result = prime
				* result
				+ ((requestParameters == null) ? 0 : requestParameters
						.hashCode());
		result = prime * result
				+ ((resourceIds == null) ? 0 : resourceIds.hashCode());
		result = prime * result + ((scope == null) ? 0 : scope.hashCode());
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
		if (!(obj instanceof StoredRequest)) {
			return false;
		}
		StoredRequest other = (StoredRequest) obj;
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
		if (clientId == null) {
			if (other.clientId != null) {
				return false;
			}
		} else if (!clientId.equals(other.clientId)) {
			return false;
		}
		if (requestParameters == null) {
			if (other.requestParameters != null) {
				return false;
			}
		} else if (!requestParameters.equals(other.requestParameters)) {
			return false;
		}
		if (resourceIds == null) {
			if (other.resourceIds != null) {
				return false;
			}
		} else if (!resourceIds.equals(other.resourceIds)) {
			return false;
		}
		if (scope == null) {
			if (other.scope != null) {
				return false;
			}
		} else if (!scope.equals(other.scope)) {
			return false;
		}
		return true;
	}
	
}
