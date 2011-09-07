package org.springframework.security.oauth2.provider;

import java.util.Collection;
import java.util.Collections;
import java.util.Set;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

/**
 * Base class for client authentication requests.
 * 
 * @author Ryan Heaton
 */
public abstract class ClientAuthenticationToken extends AbstractAuthenticationToken {

	private final String clientId;
	private final String clientSecret;
	private final Set<String> scope;
	private final Set<String> resourceIds;

	protected ClientAuthenticationToken(String clientId, String clientSecret, Set<String> scope) {
		this(clientId, null, clientSecret, scope, null, false);
	}

	protected ClientAuthenticationToken(String clientId, Set<String> resourceIds, String clientSecret, Set<String> scope) {
		this(clientId, resourceIds, clientSecret, scope, null, false);
	}

	protected ClientAuthenticationToken(String clientId, Set<String> resourceIds, String clientSecret, Set<String> scope, Collection<GrantedAuthority> authorities) {
		this(clientId, resourceIds, clientSecret, scope, authorities, true);
	}

	private ClientAuthenticationToken(String clientId, Set<String> resourceIds,  String clientSecret, Set<String> scope,
			Collection<GrantedAuthority> authorities, boolean authenticated) {
		super(authorities);
		this.clientId = clientId;
		this.resourceIds = resourceIds;
		this.clientSecret = clientSecret;
		this.scope = scope;
		setAuthenticated(authenticated);
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

}