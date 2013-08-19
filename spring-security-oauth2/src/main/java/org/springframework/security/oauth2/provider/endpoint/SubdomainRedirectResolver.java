package org.springframework.security.oauth2.provider.endpoint;

import java.net.URI;
import java.net.URISyntaxException;

import org.apache.log4j.Logger;

/**
 * there are cases where the we would like to allow all subdomains from a specific domain 
 * (or other cases that regex might help to solve). this redirect resolver allows to use regex 
 * for this purpose.
 * 
 * @author Ohad Redlich
 *
 */
public class SubdomainRedirectResolver extends DefaultRedirectResolver
{
    private static final Logger log = Logger.getLogger(SubdomainRedirectResolver.class);

    
    /**
	 * 
	 * @param requestedRedirect The requested redirect URI.
	 * @param registeredHost The registered redirect URI - main domain.
	 * @return Whether the requested redirect URI "matches" the specified redirect URI.
	 */
	@Override
	protected boolean redirectMatches(String requestedRedirect, String registeredHost) 
	{
		String requestedHost = null;
		try
		{
			URI requesrtedUri = new URI(requestedRedirect);
						
			requestedHost = requesrtedUri.getHost();
		}
		catch (URISyntaxException e)
		{
			log.info("redirect-uri could not be parsed as a valid URI, delegating call to super; URI: " + requestedRedirect );
			return super.redirectMatches(requestedRedirect, registeredHost);
		}
		boolean val = requestedHost.endsWith(registeredHost);
		if(!val)
		{
			log.error("redirect resloving failed, registered host: " + registeredHost + ", found: " + requestedHost);
		}
		return val;
	}

}
