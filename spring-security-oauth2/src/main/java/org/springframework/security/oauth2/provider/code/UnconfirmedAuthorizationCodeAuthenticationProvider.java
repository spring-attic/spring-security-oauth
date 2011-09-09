package org.springframework.security.oauth2.provider.code;

import java.util.Set;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.common.exceptions.RedirectMismatchException;
import org.springframework.security.oauth2.provider.AccessGrantAuthenticationToken;
import org.springframework.security.oauth2.provider.ClientAuthenticationToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * Authentication provider that supplies an auth token in exchange for an authorization code.
 * 
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class UnconfirmedAuthorizationCodeAuthenticationProvider implements AuthenticationProvider, InitializingBean {

	private AuthenticationManager authenticationManager;
	private AuthorizationCodeServices authorizationCodeServices;

	public void afterPropertiesSet() throws Exception {
		Assert.notNull(this.authenticationManager, "An authentication manager must be provided.");
		Assert.notNull(this.authorizationCodeServices, "Authorization code services must be supplied.");
	}

	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		AuthorizationCodeAuthenticationToken auth = (AuthorizationCodeAuthenticationToken) authentication;
		String authorizationCode = auth.getAuthorizationCode();
		if (authorizationCode == null) {
			throw new OAuth2Exception("An authorization code must be supplied.");
		}

		UnconfirmedAuthorizationCodeAuthenticationTokenHolder storedAuth = getAuthorizationCodeServices()
				.consumeAuthorizationCode(authorizationCode);
		if (storedAuth == null) {
			throw new InvalidGrantException("Invalid authorization code: " + authorizationCode);
		}

		UnconfirmedAuthorizationCodeAuthenticationToken unconfirmedAuthorizationCodeAuth = storedAuth
				.getClientAuthentication();
		if (unconfirmedAuthorizationCodeAuth.getRequestedRedirect() != null
				&& !unconfirmedAuthorizationCodeAuth.getRequestedRedirect().equals(auth.getRequestedRedirect())) {
			throw new RedirectMismatchException("Redirect URI mismatch.");
		}

		if (auth.getClientId() != null && !auth.getClientId().equals(unconfirmedAuthorizationCodeAuth.getClientId())) {
			// just a sanity check.
			throw new InvalidClientException("Client ID mismatch");
		}
		if (auth.getClientSecret() != null && !auth.getClientSecret().equals(unconfirmedAuthorizationCodeAuth.getClientSecret())) {
			// just a sanity check.
			throw new InvalidClientException("Client secret mismatch");
		}

		if (StringUtils.hasText(auth.getState()) && !auth.getState().equals(unconfirmedAuthorizationCodeAuth.getState())) {
			// just a sanity check.
			throw new InvalidRequestException("State mismatch");
		}
		if (StringUtils.hasText(unconfirmedAuthorizationCodeAuth.getState()) && !unconfirmedAuthorizationCodeAuth.getState().equals(auth.getState())) {
			// just a sanity check.
			throw new InvalidRequestException("State mismatch");
		}
		
		Set<String> unconfirmedAuthorizationScope = unconfirmedAuthorizationCodeAuth.getScope();
		Set<String> authorizationScope = auth.getScope();
		if (!unconfirmedAuthorizationScope.containsAll(authorizationScope)) {
			throw new InvalidScopeException("Request for access token scope outside of authorization code scope.");
		}
		if (authorizationScope.isEmpty()) {
			authorizationScope = unconfirmedAuthorizationScope;
		}

		AccessGrantAuthenticationToken confirmedAuth = new AccessGrantAuthenticationToken(unconfirmedAuthorizationCodeAuth.getClientId(),
				unconfirmedAuthorizationCodeAuth.getClientSecret(), authorizationScope, "authorization_code");
		ClientAuthenticationToken clientAuth = (ClientAuthenticationToken) getAuthenticationManager().authenticate(
				confirmedAuth);
		Authentication userAuth = storedAuth.getUserAuthentication();
		return new OAuth2Authentication(clientAuth, userAuth);
	}

	public boolean supports(Class authentication) {
		return AuthorizationCodeAuthenticationToken.class.isAssignableFrom(authentication);
	}

	public AuthenticationManager getAuthenticationManager() {
		return authenticationManager;
	}

	@Autowired
	public void setAuthenticationManager(AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
	}

	public AuthorizationCodeServices getAuthorizationCodeServices() {
		return authorizationCodeServices;
	}

	@Autowired
	public void setAuthorizationCodeServices(AuthorizationCodeServices authorizationCodeServices) {
		this.authorizationCodeServices = authorizationCodeServices;
	}

}