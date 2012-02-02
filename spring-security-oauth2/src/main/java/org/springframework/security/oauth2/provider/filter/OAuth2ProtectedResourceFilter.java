package org.springframework.security.oauth2.provider.filter;

import java.io.IOException;
import java.util.Collection;
import java.util.Enumeration;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;

/**
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class OAuth2ProtectedResourceFilter extends GenericFilterBean {

	private ResourceServerTokenServices tokenServices;

	private String resourceId;

	@Override
	public void afterPropertiesSet() throws ServletException {
		super.afterPropertiesSet();
		Assert.notNull(tokenServices, "OAuth 2 token services must be supplied.");
	}

	public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain)
			throws IOException, ServletException {

		HttpServletRequest request = (HttpServletRequest) servletRequest;
		HttpServletResponse response = (HttpServletResponse) servletResponse;

		String token = parseToken(request);
		if (token != null) {
			OAuth2Authentication auth = tokenServices.loadAuthentication(token);

			if (auth == null) {
				throw new InvalidTokenException("Invalid token: " + token);
			}

			Collection<String> resourceIds = auth.getAuthorizationRequest().getResourceIds();
			if (resourceIds != null && !resourceIds.isEmpty() && !resourceIds.contains(resourceId)) {
				throw new InvalidTokenException("Invalid token does not contain resource id (" + resourceId + "): "
						+ token);
			}

			SecurityContextHolder.getContext().setAuthentication(auth);
		}

		chain.doFilter(request, response);

		if (logger.isDebugEnabled()) {
			logger.debug("Chain processed normally");
		}

	}

	protected String parseToken(HttpServletRequest request) {
		// first check the header...
		String token = parseHeaderToken(request);

		// bearer type allows a request parameter as well
		if (token == null) {
			logger.debug("Token not found in headers. Trying request parameters.");
			token = request.getParameter(OAuth2AccessToken.ACCESS_TOKEN);
			if (token == null) {
				logger.debug("Token not found in request parameters.  Not an OAuth2 request.");
			}
		}

		return token;
	}

	/**
	 * Parse the OAuth header parameters. The parameters will be oauth-decoded.
	 * 
	 * @param request The request.
	 * @return The parsed parameters, or null if no OAuth authorization header was supplied.
	 */
	protected String parseHeaderToken(HttpServletRequest request) {
		@SuppressWarnings("unchecked")
		Enumeration<String> headers = request.getHeaders("Authorization");
		while (headers.hasMoreElements()) {
			String value = headers.nextElement();
			if ((value.toLowerCase().startsWith(OAuth2AccessToken.BEARER_TYPE.toLowerCase()))) {
				String authHeaderValue = value.substring(OAuth2AccessToken.BEARER_TYPE.length()).trim();

				if (authHeaderValue.contains("oauth_signature_method") || authHeaderValue.contains("oauth_verifier")) {
					// presence of oauth_signature_method or oauth_verifier implies an oauth 1.x request
					continue;
				}

				int commaIndex = authHeaderValue.indexOf(',');
				if (commaIndex > 0) {
					authHeaderValue = authHeaderValue.substring(0, commaIndex);
				}

				// todo: parse any parameters...

				return authHeaderValue;
			}
			else {
				// todo: support additional authorization schemes for different token types, e.g. "MAC" specified by
				// http://tools.ietf.org/html/draft-hammer-oauth-v2-mac-token
			}
		}

		return null;
	}

	@Autowired
	public void setTokenServices(ResourceServerTokenServices tokenServices) {
		this.tokenServices = tokenServices;
	}

	public void setResourceId(String resourceId) {
		this.resourceId = resourceId;
	}

}
