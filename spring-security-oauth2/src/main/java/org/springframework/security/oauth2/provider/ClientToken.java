package org.springframework.security.oauth2.provider;

import java.io.Serializable;
import java.util.Collection;
import java.util.Collections;
import java.util.Set;

import org.springframework.security.core.GrantedAuthority;

/**
 * Base class representing a client inside the OAuth2 provider.
 * 
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class ClientToken implements Serializable {

	private final String clientId;
	private final String clientSecret;
	private final Set<String> scope;
	private final Set<String> resourceIds;
	private boolean approved;
	private final Collection<GrantedAuthority> authorities;

	public ClientToken(String clientId, String clientSecret, Set<String> scope) {
		this(clientId, null, clientSecret, scope, null, false);
	}

	public ClientToken(String clientId, Set<String> resourceIds, String clientSecret, Set<String> scope, Collection<GrantedAuthority> authorities) {
		this(clientId, resourceIds, clientSecret, scope, authorities, true);
	}

	private ClientToken(String clientId, Set<String> resourceIds, String clientSecret, Set<String> scope,
			Collection<GrantedAuthority> authorities, boolean approved) {
		this.clientId = clientId;
		this.resourceIds = resourceIds;
		this.clientSecret = clientSecret;
		this.scope = scope;
		this.authorities = authorities;
		this.approved = approved;
	}

	public String getClientId() {
		return this.clientId;
	}

	public Object getPrincipal() {
		return getClientId();
	}

	public String getClientSecret() {
		return this.clientSecret;
	}

	public Object getCredentials() {
		return getClientSecret();
	}

	public Set<String> getScope() {
		return this.scope == null ? Collections.<String> emptySet() : this.scope;
	}

	public Set<String> getResourceIds() {
		return resourceIds;
	}
	
	public Collection<GrantedAuthority> getAuthorities() {
		return authorities;
	}
	
	public boolean isAuthenticated() {
		return approved;
	}

	// TODO: Make this immutable
	protected void setApproved(boolean approved) {
		this.approved = approved;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + (approved ? 1231 : 1237);
		result = prime * result + ((authorities == null) ? 0 : authorities.hashCode());
		result = prime * result + ((clientId == null) ? 0 : clientId.hashCode());
		result = prime * result + ((clientSecret == null) ? 0 : clientSecret.hashCode());
		result = prime * result + ((resourceIds == null) ? 0 : resourceIds.hashCode());
		result = prime * result + ((scope == null) ? 0 : scope.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		ClientToken other = (ClientToken) obj;
		if (approved != other.approved)
			return false;
		if (authorities == null) {
			if (other.authorities != null)
				return false;
		} else if (!authorities.equals(other.authorities))
			return false;
		if (clientId == null) {
			if (other.clientId != null)
				return false;
		} else if (!clientId.equals(other.clientId))
			return false;
		if (clientSecret == null) {
			if (other.clientSecret != null)
				return false;
		} else if (!clientSecret.equals(other.clientSecret))
			return false;
		if (resourceIds == null) {
			if (other.resourceIds != null)
				return false;
		} else if (!resourceIds.equals(other.resourceIds))
			return false;
		if (scope == null) {
			if (other.scope != null)
				return false;
		} else if (!scope.equals(other.scope))
			return false;
		return true;
	}
	
}