package org.springframework.security.oauth2.client.resource;

import java.util.List;

import org.springframework.security.oauth2.common.AuthenticationScheme;

/**
 * Details for an OAuth2-protected resource.
 * 
 * @author Ryan Heaton
 * @author Dave Syer
 */
public interface OAuth2ProtectedResourceDetails {

	/**
	 * Get a unique identifier for these protected resource details.
	 * 
	 * @return A unique identifier for these protected resource details.
	 */
	public String getId();

	/**
	 * The client identifier to use for this protected resource.
	 * 
	 * @return The client identifier to use for this protected resource.
	 */
	public String getClientId();

	/**
	 * The URL to use to obtain an OAuth2 access token.
	 * 
	 * @return The URL to use to obtain an OAuth2 access token.
	 */
	String getAccessTokenUri();

	/**
	 * Whether this resource is limited to a specific scope. If false, the scope of the authentication request will be
	 * ignored.
	 * 
	 * @return Whether this resource is limited to a specific scope.
	 */
	boolean isScoped();

	/**
	 * The scope of this resource. Ignored if the {@link #isScoped() resource isn't scoped}.
	 * 
	 * @return The scope of this resource.
	 */
	List<String> getScope();

	/**
	 * Whether a secret is required to obtain an access token to this resource.
	 * 
	 * @return Whether a secret is required to obtain an access token to this resource.
	 */
	boolean isAuthenticationRequired();

	/**
	 * The client secret. Ignored if the {@link #isAuthenticationRequired() secret isn't required}.
	 * 
	 * @return The client secret.
	 */
	String getClientSecret();

	/**
	 * The scheme to use to authenticate the client. E.g. "header" or "query".
	 * 
	 * @return The scheme used to authenticate the client.
	 */
	AuthenticationScheme getClientAuthenticationScheme();

	/**
	 * The grant type for obtaining an acces token for this resource.
	 * 
	 * @return The grant type for obtaining an acces token for this resource.
	 */
	String getGrantType();

	/**
	 * Get the bearer token method for this resource.
	 * 
	 * @return The bearer token method for this resource.
	 */
	AuthenticationScheme getAuthenticationScheme();

	/**
	 * The name of the bearer token. The default is "access_token", which is according to the spec, but some providers
	 * (e.g. Facebook) don't conform to the spec.)
	 * 
	 * @return The name of the bearer token.
	 */
	String getTokenName();

	/**
	 * A flag to indicate that this resource is only to be used with client credentials, thus allowing access tokens to
	 * be cached independent of a user's session.
	 * 
	 * @return true if this resource is only used with client credentials grant
	 */
	public boolean isClientOnly();
}
