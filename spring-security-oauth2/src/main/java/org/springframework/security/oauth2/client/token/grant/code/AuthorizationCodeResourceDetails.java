package org.springframework.security.oauth2.client.token.grant.code;

import org.springframework.security.oauth2.client.token.grant.redirect.AbstractRedirectResourceDetails;

/**
 * <p>
 * @deprecated See the <a href="https://github.com/spring-projects/spring-security/wiki/OAuth-2.0-Migration-Guide">OAuth 2.0 Migration Guide</a> for Spring Security 5.
 *
 * @author Ryan Heaton
 * @author Dave Syer
 */
@Deprecated
public class AuthorizationCodeResourceDetails extends AbstractRedirectResourceDetails {

	public AuthorizationCodeResourceDetails() {
		setGrantType("authorization_code");
	}

}
