package org.springframework.security.oauth2.provider;

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
public class StoredRequest {
	
	private String clientId;
	private Set<GrantedAuthority> authorities;
	private boolean approved;
	private Set<String> scope;
	private Set<String> resourceIds;
	private Map<String, String> requestParameters;
	
	public StoredRequest(Map<String, String> requestParameters, String clientId, Collection<? extends GrantedAuthority> authorities, boolean approved, Set<String> scope, Set<String> resourceIds) {
		this.requestParameters = requestParameters;
		this.clientId = clientId;
		this.authorities = new HashSet<GrantedAuthority>(authorities);
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
	
}
