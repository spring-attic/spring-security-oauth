package org.springframework.security.oauth2.provider.refresh;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.provider.ClientAuthenticationToken;

import java.util.Collection;
import java.util.Set;

/**
 * An authentication token that was issued from a refresh token.
 *
 * @author Ryan Heaton
 */
public class RefreshedAuthenticationToken extends ClientAuthenticationToken {

	public RefreshedAuthenticationToken(String clientId, Set<String> resourceIds, String clientSecret, Set<String> scope, Collection<GrantedAuthority> authorities) {
		super(clientId, resourceIds, clientSecret, scope, authorities);
	}
}
