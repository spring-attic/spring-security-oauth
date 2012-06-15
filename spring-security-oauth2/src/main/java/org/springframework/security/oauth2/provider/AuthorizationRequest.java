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
 * @author Amanda Anganes
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

	private final Map<String, String> approvalParameters = new HashMap<String, String>();

	public static final String USER_OAUTH_APPROVAL = "user_oauth_approval";

	public AuthorizationRequest(Map<String, String> authorizationParameters) {
		this(authorizationParameters, Collections.<String, String> emptyMap(), authorizationParameters.get(CLIENT_ID),
				OAuth2Utils.parseParameterList(authorizationParameters.get("scope")), null, null, false);
		// This is unapproved by default since only the authorizationParameters are available
		for (String key : authorizationParameters.keySet()) {
			if (key.equals(SCOPE)) {
				this.authorizationParameters.put(SCOPE, OAuth2Utils.formatParameterList(scope));
			}
			else {
				this.authorizationParameters.put(key, authorizationParameters.get(key));
			}
		}
	}

	public AuthorizationRequest(Map<String, String> authorizationParameters, Map<String, String> approvalParameters,
			String clientId, Collection<String> scope) {
		this(authorizationParameters, approvalParameters, clientId, scope, null, null, false);
	}

	public AuthorizationRequest(String clientId, Collection<String> scope) {
		this(null, null, clientId, scope, null, null, false);
	}

	private AuthorizationRequest(AuthorizationRequest copy, boolean approved) {
		this(copy.authorizationParameters, copy.approvalParameters, copy.getClientId(), copy.scope, copy.authorities,
				copy.resourceIds, approved);
		if (!scope.isEmpty()) {
			this.authorizationParameters.put(SCOPE, OAuth2Utils.formatParameterList(scope));
		}
	}

	private AuthorizationRequest(AuthorizationRequest copy, Map<String, String> userConsentParameters) {
		this(copy.authorizationParameters, userConsentParameters, copy.getClientId(), copy.scope, copy.authorities,
				copy.resourceIds, copy.approved);
		if (!scope.isEmpty()) {
			this.authorizationParameters.put(SCOPE, OAuth2Utils.formatParameterList(scope));
		}
	}

	private AuthorizationRequest(Map<String, String> authorizationParameters, Map<String, String> approvalParameters,
			String clientId, Collection<String> scope, Collection<GrantedAuthority> authorities,
			Collection<String> resourceIds, boolean approved) {
		if (authorizationParameters != null) {
			this.authorizationParameters.putAll(authorizationParameters);
		}
		if (approvalParameters != null) {
			this.approvalParameters.putAll(approvalParameters);
		}
		this.resourceIds = resourceIds == null ? Collections.<String> emptySet() : new HashSet<String>(resourceIds);
		this.scope = scope == null ? Collections.<String> emptySet() : new LinkedHashSet<String>(scope);
		this.authorities = authorities == null ? Collections.<GrantedAuthority> emptySet()
				: new HashSet<GrantedAuthority>(authorities);
		this.authorizationParameters.put(CLIENT_ID, clientId);
		this.authorizationParameters.put(SCOPE, OAuth2Utils.formatParameterList(scope));
		this.approved = approved;
	}

	public Map<String, String> getAuthorizationParameters() {
		return Collections.unmodifiableMap(authorizationParameters);
	}

	public AuthorizationRequest addApprovalParameters(Map<String, String> parameters) {
		return parameters == null ? this : new AuthorizationRequest(this, parameters);
	}

	public Map<String, String> getApprovalParameters() {
		return Collections.unmodifiableMap(approvalParameters);
	}

	public String getClientId() {
		return authorizationParameters.get(CLIENT_ID);
	}

	public Set<String> getScope() {
		return this.scope;
	}

	public Set<String> getResourceIds() {
		return Collections.unmodifiableSet(resourceIds);
	}

	public Collection<GrantedAuthority> getAuthorities() {
		return Collections.unmodifiableSet((Set<? extends GrantedAuthority>) authorities);
	}

	public boolean isApproved() {
		return approved;
	}

	public boolean isDenied() {
		return !approved;
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

	public AuthorizationRequest approved(boolean approved) {
		return new AuthorizationRequest(this, approved);
	}

	public AuthorizationRequest resolveRedirectUri(String redirectUri) {
		AuthorizationRequest result = new AuthorizationRequest(this, approved);
		result.authorizationParameters.put(REDIRECT_URI, redirectUri);
		return result;
	}

	public AuthorizationRequest addClientDetails(ClientDetails clientDetails) {
		AuthorizationRequest result = new AuthorizationRequest(this, approved);
		result.resourceIds.addAll(clientDetails.getResourceIds());
		result.authorities.addAll(clientDetails.getAuthorities());
		return result;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((authorities == null) ? 0 : authorities.hashCode());
		result = prime * result + (approved ? 1231 : 1237);
		result = prime * result + ((authorizationParameters == null) ? 0 : authorizationParameters.hashCode());
		result = prime * result + ((approvalParameters == null) ? 0 : approvalParameters.hashCode());
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
		if (approvalParameters == null) {
			if (other.approvalParameters != null)
				return false;
		}
		else if (!approvalParameters.equals(other.approvalParameters))
			return false;
		return true;
	}

}