package org.springframework.security.oauth2.provider;

import java.io.Serializable;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.common.util.OAuth2Utils;

/**
 * Base class representing a request for authorization. There are convenience methods for the well-known properties
 * required by the OAUth2 spec, and a set of generic parameters to allow for extensions.
 * 
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class AuthorizationRequest implements Serializable {

	private static final String CLIENT_ID = "client_id";

	private static final String STATE = "state";

	private static final String SCOPE = "scope";

	private static final String REDIRECT_URI = "redirect_uri";

	private final Set<String> scope;

	private final Set<String> resourceIds;

	private final boolean denied;

	private final Collection<GrantedAuthority> authorities;

	private final Map<String, String> parameters = new HashMap<String, String>();

	public AuthorizationRequest(Map<String, String> parameters) {
		this(parameters.get(CLIENT_ID), OAuth2Utils.parseParameterList(parameters.get("scope")), null, null, false,
				parameters.get(STATE), parameters.get(REDIRECT_URI));
		this.parameters.putAll(parameters);
	}

	public AuthorizationRequest(String clientId, Collection<String> scope, Collection<GrantedAuthority> authorities,
			Collection<String> resourceIds) {
		this(clientId, scope, authorities, resourceIds, false, null, null);
	}

	private AuthorizationRequest(AuthorizationRequest copy, boolean denied) {
		this(copy.getClientId(), copy.scope, copy.authorities, copy.resourceIds, denied, copy.getState(), copy
				.getRedirectUri());
		this.parameters.putAll(copy.parameters);
	}

	private AuthorizationRequest(String clientId, Collection<String> scope, Collection<GrantedAuthority> authorities,
			Collection<String> resourceIds, boolean denied, String state, String requestedRedirect) {
		this.resourceIds = resourceIds == null ? null : Collections.unmodifiableSet(new HashSet<String>(resourceIds));
		this.scope = scope == null ? Collections.<String> emptySet() : Collections.unmodifiableSet(new HashSet<String>(
				scope));
		this.authorities = authorities == null ? null : new HashSet<GrantedAuthority>(authorities);
		this.denied = denied;
		parameters.put(CLIENT_ID, clientId);
		parameters.put(STATE, state);
		parameters.put(REDIRECT_URI, requestedRedirect);
		parameters.put(SCOPE, OAuth2Utils.formatParameterList(scope));
	}

	public Map<String, String> getParameters() {
		return Collections.unmodifiableMap(parameters);
	}

	public String getClientId() {
		return parameters.get(CLIENT_ID);
	}

	public Set<String> getScope() {
		return this.scope;
	}

	public Set<String> getResourceIds() {
		return resourceIds;
	}

	public Collection<GrantedAuthority> getAuthorities() {
		return authorities;
	}

	public boolean isAuthenticated() {
		return !denied;
	}

	public boolean isDenied() {
		return denied;
	}

	public AuthorizationRequest denied(boolean denied) {
		return new AuthorizationRequest(this, denied);
	}

	public AuthorizationRequest resolveRedirectUri(String redirectUri) {
		AuthorizationRequest result = new AuthorizationRequest(this, denied);
		result.parameters.put(REDIRECT_URI, redirectUri);
		return result;
	}

	public String getState() {
		return parameters.get(STATE);
	}

	public String getRedirectUri() {
		return parameters.get(REDIRECT_URI);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((authorities == null) ? 0 : authorities.hashCode());
		result = prime * result + (denied ? 1231 : 1237);
		result = prime * result + ((parameters == null) ? 0 : parameters.hashCode());
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
		AuthorizationRequest other = (AuthorizationRequest) obj;
		if (authorities == null) {
			if (other.authorities != null)
				return false;
		}
		else if (!authorities.equals(other.authorities))
			return false;
		if (denied != other.denied)
			return false;
		if (parameters == null) {
			if (other.parameters != null)
				return false;
		}
		else if (!parameters.equals(other.parameters))
			return false;
		if (resourceIds == null) {
			if (other.resourceIds != null)
				return false;
		}
		else if (!resourceIds.equals(other.resourceIds))
			return false;
		if (scope == null) {
			if (other.scope != null)
				return false;
		}
		else if (!scope.equals(other.scope))
			return false;
		return true;
	}

}