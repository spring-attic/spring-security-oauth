package org.springframework.security.oauth2.provider.vote;

import java.util.Collection;
import java.util.Set;

import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.common.exceptions.InsufficientScopeException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;

/**
 * This voter checks scope in request is consistent with that held by the client. If there is no user in the request
 * (client_credentials grant) it checks against authorities of client instead of scopes by default. Activate by adding
 * <code>CLIENT_HAS_SCOPE</code> to security attributes.
 * 
 * @author Dave Syer
 * 
 */
public class ClientScopeVoter implements AccessDecisionVoter<Object> {

	private String clientHasScope = "CLIENT_HAS_SCOPE";

	private boolean throwException = true;

	private ClientDetailsService clientDetailsService;

	private boolean clientAuthoritiesAreScopes = true;

	/**
	 * ClientDetailsService for looking up clients by ID.
	 * 
	 * @param clientDetailsService the client details service (mandatory)
	 */
	public void setClientDetailsService(ClientDetailsService clientDetailsService) {
		this.clientDetailsService = clientDetailsService;
	}

	/**
	 * Flag to determine the behaviour on access denied. If set then we throw an {@link InsufficientScopeException}
	 * instead of returning {@link AccessDecisionVoter#ACCESS_DENIED}. This is unconventional for an access decision
	 * voter because it vetos the other voters in the chain, but it enables us to pass a message to the caller with
	 * information about the required scope.
	 * 
	 * @param throwException the flag to set (default true)
	 */
	public void setThrowException(boolean throwException) {
		this.throwException = throwException;
	}

	/**
	 * Flag to signal that when there is no user authentication client authorities are to be treated as scopes.
	 * 
	 * @param clientAuthoritiesAreScopes the flag value (default true)
	 */
	public void setClientAuthoritiesAreScopes(boolean clientAuthoritiesAreScopes) {
		this.clientAuthoritiesAreScopes = clientAuthoritiesAreScopes;
	}

	/**
	 * The name of the config attribute that can be used to deny access to OAuth2 client. Defaults to
	 * <code>DENY_OAUTH</code>.
	 * 
	 * @param denyAccess the deny access attribute value to set
	 */
	public void setDenyAccess(String denyAccess) {
		this.clientHasScope = denyAccess;
	}

	public boolean supports(ConfigAttribute attribute) {
		if (clientHasScope.equals(attribute.getAttribute())) {
			return true;
		}
		else {
			return false;
		}
	}

	/**
	 * This implementation supports any type of class, because it does not query the presented secure object.
	 * 
	 * @param clazz the secure object
	 * 
	 * @return always <code>true</code>
	 */
	public boolean supports(Class<?> clazz) {
		return true;
	}

	public int vote(Authentication authentication, Object object, Collection<ConfigAttribute> attributes) {

		int result = ACCESS_ABSTAIN;

		if (!(authentication instanceof OAuth2Authentication)) {
			return result;
		}

		OAuth2Authentication oauth2Authentication = (OAuth2Authentication) authentication;
		OAuth2Request clientAuthentication = oauth2Authentication.getOAuth2Request();
		ClientDetails client = clientDetailsService.loadClientByClientId(clientAuthentication.getClientId());
		Set<String> scopes = clientAuthentication.getScope();
		if (oauth2Authentication.isClientOnly() && clientAuthoritiesAreScopes) {
			scopes = AuthorityUtils.authorityListToSet(clientAuthentication.getAuthorities());
		}

		for (ConfigAttribute attribute : attributes) {
			if (this.supports(attribute)) {

				result = ACCESS_GRANTED;

				for (String scope : scopes) {
					if (!client.getScope().contains(scope)) {
						result = ACCESS_DENIED;
						break;
					}
				}

				if (result == ACCESS_DENIED && throwException) {
					InsufficientScopeException failure = new InsufficientScopeException(
							"Insufficient scope for this resource", client.getScope());
					throw new AccessDeniedException(failure.getMessage(), failure);
				}

				return result;
			}
		}

		return result;
	}

}
