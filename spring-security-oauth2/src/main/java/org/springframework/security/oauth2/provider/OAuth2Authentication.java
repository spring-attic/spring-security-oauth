package org.springframework.security.oauth2.provider;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;

/**
 * An OAuth 2 authentication token can contain two authentications: one for the client and one for the user. Since some
 * OAuth authorization grants don't require user authentication, the user authentication may be null.
 * 
 * @author Ryan Heaton
 */
public class OAuth2Authentication extends AbstractAuthenticationToken {

	private static final long serialVersionUID = -4809832298438307309L;

	private final OAuth2Request storedRequest;

	private final Authentication userAuthentication;

	/**
	 * Construct an OAuth 2 authentication. Since some grant types don't require user authentication, the user
	 * authentication may be null.
	 * 
	 * @param storedRequest The authorization request (must not be null).
	 * @param userAuthentication The user authentication (possibly null).
	 */
	public OAuth2Authentication(OAuth2Request storedRequest, Authentication userAuthentication) {
		super(userAuthentication == null ? storedRequest.getAuthorities() : userAuthentication.getAuthorities());
		this.storedRequest = storedRequest;
		this.userAuthentication = userAuthentication;
	}

	public Object getCredentials() {
		return "";
	}

	public Object getPrincipal() {
		return this.userAuthentication == null ? this.storedRequest.getClientId() : this.userAuthentication
				.getPrincipal();
	}

	/**
	 * Convenience method to check if there is a user associated with this token, or just a client application.
	 * 
	 * @return true if this token represents a client app not acting on behalf of a user
	 */
	public boolean isClientOnly() {
		return userAuthentication == null;
	}

	/**
	 * The authorization request containing details of the client application.
	 * 
	 * @return The client authentication.
	 */
	public OAuth2Request getOAuth2Request() {
		return storedRequest;
	}

	/**
	 * The user authentication.
	 * 
	 * @return The user authentication.
	 */
	public Authentication getUserAuthentication() {
		return userAuthentication;
	}

	@Override
	public boolean isAuthenticated() {
		return this.storedRequest.isApproved()
				&& (this.userAuthentication == null || this.userAuthentication.isAuthenticated());
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (!(o instanceof OAuth2Authentication)) {
			return false;
		}
		if (!super.equals(o)) {
			return false;
		}

		OAuth2Authentication that = (OAuth2Authentication) o;

		if (!storedRequest.equals(that.storedRequest)) {
			return false;
		}
		if (userAuthentication != null ? !userAuthentication.equals(that.userAuthentication)
				: that.userAuthentication != null) {
			return false;
		}
		
		if (getDetails()!=null ? !getDetails().equals(that.getDetails()) : that.getDetails()!=null) {
			// return false;
		}

		return true;
	}

	@Override
	public int hashCode() {
		int result = super.hashCode();
		result = 31 * result + storedRequest.hashCode();
		result = 31 * result + (userAuthentication != null ? userAuthentication.hashCode() : 0);
		return result;
	}

}
