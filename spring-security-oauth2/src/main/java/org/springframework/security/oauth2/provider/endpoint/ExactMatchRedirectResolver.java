package org.springframework.security.oauth2.provider.endpoint;



/**
 * Strict implementation for a redirect resolver which requires
 * an exact match between the registered and requested redirect_uri.
 *
 * <p>
 * @deprecated See the <a href="https://github.com/spring-projects/spring-security/wiki/OAuth-2.0-Migration-Guide">OAuth 2.0 Migration Guide</a> for Spring Security 5.
 *
 * @author Ryan Heaton
 * @author Dave Syer
 */
@Deprecated
public class ExactMatchRedirectResolver extends DefaultRedirectResolver {

	/**
	 * Whether the requested redirect URI "matches" the specified redirect URI. This implementation tests strict
	 * equality.
	 *
	 * @param requestedRedirect The requested redirect URI.
	 * @param redirectUri The registered redirect URI.
	 * @return Whether the requested redirect URI "matches" the specified redirect URI.
	 */
	protected boolean redirectMatches(String requestedRedirect, String redirectUri) {
		return requestedRedirect.equals(redirectUri);
	}

}
