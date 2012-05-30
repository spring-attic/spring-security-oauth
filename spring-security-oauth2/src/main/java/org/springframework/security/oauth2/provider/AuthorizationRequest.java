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
 * Base class representing a request for authorization. There are convenience methods for the well-known properties
 * required by the OAUth2 spec, and a set of generic authorizationParameters to allow for extensions.
 * 
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class AuthorizationRequest implements Serializable {

	private static final String CLIENT_ID = "client_id";

	private static final String STATE = "state";

	private static final String SCOPE = "scope";

	private static final String REDIRECT_URI = "redirect_uri";

	private static final String RESPONSE_TYPE = "response_type";

	private final Set<String> scope;

	private final Set<String> resourceIds;

	private final boolean approved;

	private final Collection<GrantedAuthority> authorities;

	private final Map<String, String> authorizationParameters = new HashMap<String, String>();
	
	private final Map<String, String> userConsentParameters = new HashMap<String, String>();

	public AuthorizationRequest(Map<String, String> parameters) {
		this(parameters, parameters.get(CLIENT_ID), OAuth2Utils.parseParameterList(parameters.get("scope")), null,
				null, null, Collections.<String, String> emptyMap());
		// This is unapproved by default since only the request authorizationParameters are available
		for (String key : parameters.keySet()) {
			if (key.equals(SCOPE)) {
				this.authorizationParameters.put(SCOPE, OAuth2Utils.formatParameterList(scope));
			}
			else {
				this.authorizationParameters.put(key, parameters.get(key));
			}
		}
	}

	public AuthorizationRequest(Map<String, String> parameters, String clientId, Collection<String> scope,
			Collection<GrantedAuthority> authorities, Collection<String> resourceIds) {
		this(parameters, clientId, scope, authorities, resourceIds, null, Collections.<String, String> emptyMap());
	}

	public AuthorizationRequest(String clientId, Collection<String> scope, Collection<GrantedAuthority> authorities,
			Collection<String> resourceIds) {
		// This is approved by default since authorities are provided so we assume the client is authenticated
		this(Collections.<String, String> emptyMap(), clientId, scope, authorities, resourceIds, null, Collections.<String, String> emptyMap());
	}

	private AuthorizationRequest(AuthorizationRequest copy, boolean approved) {
		this(copy.authorizationParameters, copy.getClientId(), copy.scope, copy.authorities, copy.resourceIds, approved, copy.userConsentParameters);
		if (!scope.isEmpty()) {
			this.authorizationParameters.put(SCOPE, OAuth2Utils.formatParameterList(scope));
		}
	}

	private AuthorizationRequest(AuthorizationRequest copy, Map<String, String> userConsentParameters) {
		this(copy.authorizationParameters, copy.getClientId(), copy.scope, copy.authorities, copy.resourceIds, copy.approved, userConsentParameters);
		if (!scope.isEmpty()) {
			this.authorizationParameters.put(SCOPE, OAuth2Utils.formatParameterList(scope));
		}
	}
	
	private AuthorizationRequest(Map<String, String> parameters, String clientId, Collection<String> scope,
			Collection<GrantedAuthority> authorities, Collection<String> resourceIds, Boolean approved, Map<String, String> userConsentParameters) {
		this.authorizationParameters.putAll(parameters);
		this.resourceIds = resourceIds == null ? null : Collections.unmodifiableSet(new HashSet<String>(resourceIds));
		this.scope = scope == null ? Collections.<String> emptySet() : Collections
				.unmodifiableSet(new LinkedHashSet<String>(scope));
		this.authorities = authorities == null ? null : new HashSet<GrantedAuthority>(authorities);
		this.approved = approved != null ? approved : authorities!=null && !authorities.isEmpty();
		this.authorizationParameters.put(CLIENT_ID, clientId);
		this.authorizationParameters.put(SCOPE, OAuth2Utils.formatParameterList(scope));
		this.userConsentParameters.putAll(userConsentParameters);
	}
	
	public Map<String, String> getAuthorizationParameters() {
		return Collections.unmodifiableMap(authorizationParameters);
	}

	public AuthorizationRequest setUserConsentParameters(Map<String, String> parameters) {
		return new AuthorizationRequest(this, parameters);
	}
	
	public Map<String, String> getUserConsentParameters() {
		return Collections.unmodifiableMap(userConsentParameters);
	}
	
	public String getClientId() {
		return authorizationParameters.get(CLIENT_ID);
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

	public boolean isApproved() {
		return approved;
	}

	public boolean isDenied() {
		return !approved;
	}
	
	public AuthorizationRequest approved(boolean approved) {
		return new AuthorizationRequest(this, approved);
	}

	public AuthorizationRequest resolveRedirectUri(String redirectUri) {
		AuthorizationRequest result = new AuthorizationRequest(this, approved);
		result.authorizationParameters.put(REDIRECT_URI, redirectUri);
		return result;
	}

	public String getState() {
		return authorizationParameters.get(STATE);
	}

	public String getRedirectUri() {
		return authorizationParameters.get(REDIRECT_URI);
	}

	public Set<String> getResponseTypes() {
		return OAuth2Utils.parseParameterList(authorizationParameters.get(RESPONSE_TYPE));
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((authorities == null) ? 0 : authorities.hashCode());
		result = prime * result + (approved ? 1231 : 1237);
		result = prime * result + ((authorizationParameters == null) ? 0 : authorizationParameters.hashCode());
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
		if (approved != other.approved)
			return false;
		if (authorizationParameters == null) {
			if (other.authorizationParameters != null)
				return false;
		}
		else if (!authorizationParameters.equals(other.authorizationParameters))
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
		if (userConsentParameters == null) {
			if (other.userConsentParameters != null) 
				return false;
		}
		else if (!userConsentParameters.equals(other.userConsentParameters))
			return false;
		return true;
	}

}