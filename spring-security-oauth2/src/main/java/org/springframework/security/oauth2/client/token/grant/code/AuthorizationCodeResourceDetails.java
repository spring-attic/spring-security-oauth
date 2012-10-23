package org.springframework.security.oauth2.client.token.grant.code;

import org.springframework.security.oauth2.client.token.grant.redirect.AbstractRedirectResourceDetails;

/**
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class AuthorizationCodeResourceDetails extends AbstractRedirectResourceDetails {

	public AuthorizationCodeResourceDetails() {
		setGrantType("authorization_code");
	}

}
