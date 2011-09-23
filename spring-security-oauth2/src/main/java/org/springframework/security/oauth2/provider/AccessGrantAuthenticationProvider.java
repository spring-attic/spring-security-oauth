package org.springframework.security.oauth2.provider;

import java.util.List;
import java.util.Set;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.encoding.PasswordEncoder;
import org.springframework.security.authentication.encoding.PlaintextPasswordEncoder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.common.exceptions.UnauthorizedClientException;
import org.springframework.util.Assert;

/**
 * Authentication provider for grants for access to an auth token.
 * 
 * @author Ryan Heaton
 */
public class AccessGrantAuthenticationProvider implements AuthenticationProvider, InitializingBean {

	private ClientDetailsService clientDetailsService;
	private PasswordEncoder passwordEncoder = new PlaintextPasswordEncoder();

	public void afterPropertiesSet() throws Exception {
		Assert.notNull(this.clientDetailsService, "Client details service must be supplied");
		Assert.notNull(this.passwordEncoder, "Password Encoder must be supplied");
	}

	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		AccessGrantAuthenticationToken clientAuth = (AccessGrantAuthenticationToken) authentication;
		ClientDetails clientDetails = getClientDetailsService().loadClientByClientId(clientAuth.getClientId());

		if (clientDetails.isSecretRequired()) {
			String assertedSecret = clientAuth.getClientSecret();
			if (assertedSecret == null) {
				throw new UnauthorizedClientException("Client secret is required but not provided.");
			} else {
				Object salt = null;
				if (clientDetails instanceof SaltedClientSecret) {
					salt = ((SaltedClientSecret) clientDetails).getSalt();
				}

				if (!getPasswordEncoder().isPasswordValid(clientDetails.getClientSecret(), assertedSecret, salt)) {
					throw new UnauthorizedClientException("Invalid client secret.");
				}
			}
		}

		// SECOAUTH-100: a refresh token grant request is OK if it has no scopes
		// TODO: check that they are picked up from the refresh token
		if (clientDetails.isScoped() && !clientAuth.getGrantType().equals("refresh_token")) {
			Set<String> requestedScope = clientAuth.getScope();
			if (requestedScope.isEmpty()) {
				throw new InvalidScopeException("Invalid scope (none)");
			}
			List<String> validScope = clientDetails.getScope();
			for (String scope : requestedScope) {
				if (!validScope.contains(scope)) {
					throw new InvalidScopeException("Invalid scope: " + scope);
				}
			}
		}

		List<String> authorizedGrantTypes = clientDetails.getAuthorizedGrantTypes();
		if (authorizedGrantTypes != null && !authorizedGrantTypes.isEmpty() && !authorizedGrantTypes.contains(clientAuth.getGrantType())) {
			throw new InvalidGrantException("Unauthorized grant type: " + clientAuth.getGrantType());
		}

		return new AuthorizedClientAuthenticationToken(clientAuth.getClientId(), clientAuth.getResourceIds(), clientAuth.getClientSecret(),
				clientAuth.getScope(), clientDetails.getAuthorities());
	}

	public boolean supports(Class<?> authentication) {
		return AccessGrantAuthenticationToken.class.isAssignableFrom(authentication);
	}

	public ClientDetailsService getClientDetailsService() {
		return clientDetailsService;
	}

	@Autowired
	public void setClientDetailsService(ClientDetailsService clientDetailsService) {
		this.clientDetailsService = clientDetailsService;
	}

	public PasswordEncoder getPasswordEncoder() {
		return passwordEncoder;
	}

	@Autowired(required = false)
	public void setPasswordEncoder(PasswordEncoder passwordEncoder) {
		this.passwordEncoder = passwordEncoder;
	}
}
