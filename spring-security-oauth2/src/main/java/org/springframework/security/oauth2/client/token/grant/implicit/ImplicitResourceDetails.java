package org.springframework.security.oauth2.client.token.grant.implicit;

import org.springframework.security.oauth2.client.token.grant.redirect.AbstractRedirectResourceDetails;

/**
 * <p>
 * @deprecated See the <a href="https://github.com/spring-projects/spring-security/wiki/OAuth-2.0-Migration-Guide">OAuth 2.0 Migration Guide</a> for Spring Security 5.
 *
 * @author Dave Syer
 */
@Deprecated
public class ImplicitResourceDetails extends AbstractRedirectResourceDetails {

	public ImplicitResourceDetails() {
		setGrantType("implicit");
	}

}
