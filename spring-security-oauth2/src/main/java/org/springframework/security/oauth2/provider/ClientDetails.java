package org.springframework.security.oauth2.provider;

import java.io.Serializable;
import java.util.Collection;
import java.util.Map;
import java.util.Set;

import org.springframework.security.core.GrantedAuthority;

/**
 * Client details for OAuth 2
 * 
 * @author Ryan Heaton
 */
public interface ClientDetails extends Serializable {

	/**
	 * The client id.
	 * 
	 * @return The client id.
	 */
	String getClientId();

	/**
	 * The resources that this client can access. Can be ignored by callers if empty.
	 * 
	 * @return The resources of this client.
	 */
	Set<String> getResourceIds();

	/**
	 * Whether a secret is required to authenticate this client.
	 * 
	 * @return Whether a secret is required to authenticate this client.
	 */
	boolean isSecretRequired();

	/**
	 * The client secret. Ignored if the {@link #isSecretRequired() secret isn't required}.
	 * 
	 * @return The client secret.
	 */
	String getClientSecret();

	/**
	 * Whether this client is limited to a specific scope. If false, the scope of the authentication request will be
	 * ignored.
	 * 
	 * @return Whether this client is limited to a specific scope.
	 */
	boolean isScoped();

	/**
	 * The scope of this client. Empty if the client isn't scoped.
	 * 
	 * @return The scope of this client.
	 */
	Set<String> getScope();

	/**
	 * The grant types for which this client is authorized.
	 * 
	 * @return The grant types for which this client is authorized.
	 */
	Set<String> getAuthorizedGrantTypes();

	/**
	 * The pre-defined redirect URI for this client to use during the "authorization_code" access grant. See OAuth spec,
	 * section 4.1.1.
	 * 
	 * @return The pre-defined redirect URI for this client.
	 */
	Set<String> getRegisteredRedirectUri();

	/**
	 * Get the authorities that are granted to the OAuth client. Note that these are NOT the authorities that are
	 * granted to the user with an authorized access token. Instead, these authorities are inherent to the client
	 * itself.
	 * 
	 * @return The authorities.
	 */
	Collection<GrantedAuthority> getAuthorities();

	/**
	 * The access token validity period for this client. Null if not set explicitly (implementations might use that fact
	 * to provide a default value for instance).
	 * 
	 * @return the access token validity period
	 */
	Integer getAccessTokenValiditySeconds();

	/**
	 * The refresh token validity period for this client. Null for default value set by token service, and 
	 * zero or negative for non-expiring tokens.
	 * 
	 * @return the refresh token validity period
	 */
	Integer getRefreshTokenValiditySeconds();
	
	/**
	 * Test whether client needs user approval for a particular scope.
	 * 
	 * @param scope the scope to consider
	 * @return true if this client does not need user approval
	 */
	boolean isAutoApprove(String scope);

	/**
	 * Additional information for this client, not needed by the vanilla OAuth protocol but might be useful, for example,
	 * for storing descriptive information.
	 * 
	 * @return a map of additional information
	 */
	Map<String, Object> getAdditionalInformation();

}
