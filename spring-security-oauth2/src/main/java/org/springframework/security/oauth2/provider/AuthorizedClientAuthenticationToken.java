package org.springframework.security.oauth2.provider;

import java.util.Collection;
import java.util.Set;

import org.springframework.security.core.GrantedAuthority;

/**
 * Authentication token for an authorized client.
 * 
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class AuthorizedClientAuthenticationToken extends ClientAuthenticationToken {

	public AuthorizedClientAuthenticationToken(String clientId, Set<String> resourceIds, String clientSecret,
			Set<String> scope, Collection<GrantedAuthority> authorities) {
		super(clientId, resourceIds, clientSecret, scope, authorities);
	}

}
