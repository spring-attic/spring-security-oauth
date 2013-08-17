package org.springframework.security.oauth2.provider.endpoint;

/**
 * there are cases where the redirect-uri consists of a subdomain, and 
 * each customer has its own subdomain, hence a different redirect-uri. So we need a resolver that will validate
 * the URL not as the default impl (that checks startsWith() ), but something that will check only the suffix 
 * of the context path.
 * 
 * @author Ohad Redlich
 *
 */
public class RegexRedirectResolver extends DefaultRedirectResolver
{
	/**
	 * Whether the requested redirect URI "matches" the specified redirect URI. This implementation tests strict
	 * equality.
	 * 
	 * @param requestedRedirect The requested redirect URI.
	 * @param redirectUri The registered redirect URI.
	 * @return Whether the requested redirect URI "matches" the specified redirect URI.
	 */
	@Override
	protected boolean redirectMatches(String requestedRedirect, String redirectUri) 
	{
		return requestedRedirect.matches( redirectUri );
	}

}
