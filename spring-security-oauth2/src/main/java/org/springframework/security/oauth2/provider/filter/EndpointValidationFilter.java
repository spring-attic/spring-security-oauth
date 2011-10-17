package org.springframework.security.oauth2.provider.filter;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.common.exceptions.UnsupportedResponseTypeException;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.bind.ServletRequestUtils;

/**
 * Validation filter for OAuth 2.0 endpoints. Ensures that clients get a 40* response for an invalid request, not a
 * regular 302 from Spring Security authentication filters. The filter also ensures that the endpoints request mapping
 * matches the incoming request, if it matches the provided {@link #setAuthorizationEndpointUrl(String)
 * authorizationEndpointUrl} or {@link #setTokenEndpointUrl(String) tokenEndpointUrl}.
 * 
 * @author Dave Syer
 */
public class EndpointValidationFilter implements Filter {

	private static final String DEFAULT_AUTHORIZATION_ENDPOINT_URL = "/oauth/authorize";

	private static final String DEFAULT_TOKEN_ENDPOINT_URL = "/oauth/token";

	private String authorizationEndpointUrl = DEFAULT_AUTHORIZATION_ENDPOINT_URL;

	private String tokenEndpointUrl = DEFAULT_TOKEN_ENDPOINT_URL;
	
	private AntPathMatcher matcher = new AntPathMatcher();

	public void destroy() {
	}

	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException,
			ServletException {
		HttpServletRequest servletRequest = (HttpServletRequest) request;
		if (matches(servletRequest, authorizationEndpointUrl)) {
			servletRequest = wrapRequest(servletRequest, DEFAULT_AUTHORIZATION_ENDPOINT_URL);
			validateAuthorizationRequest(request);
		} else if (matches(servletRequest, tokenEndpointUrl)) {
			servletRequest = wrapRequest(servletRequest, DEFAULT_TOKEN_ENDPOINT_URL);
			validateTokenRequest(request);
		}
		chain.doFilter(servletRequest, response);
	}

	protected void validateAuthorizationRequest(ServletRequest request) throws ServletException {

		// TODO: extract into a strategy
		// TODO: distinguish between GET and POST
		String responseType = ServletRequestUtils.getStringParameter(request, "response_type");
		if ("code".equals(responseType)) {
			String clientId = request.getParameter("client_id");
			if (clientId == null) {
				throw new InvalidClientException("A client_id parameter must be supplied.");
			}
		} else if ("token".equals(responseType)) {
			throw new UnsupportedResponseTypeException("Unsupported response type: token.");
		} else if ("code_and_token".equals(responseType)) {
			throw new UnsupportedResponseTypeException("Unsupported response type: code_and_token.");
		}

	}

	protected void validateTokenRequest(ServletRequest request) throws ServletException {
	}

	private HttpServletRequest wrapRequest(final HttpServletRequest request, final String urlToMatch) {
		if (matches(request, urlToMatch)) {
			return request;
		}
		return new HttpServletRequestWrapper(request) {
			@Override
			public String getRequestURI() {
				return prependContextPath(request, urlToMatch);
			}

			@Override
			public String getServletPath() {
				return urlToMatch;
			}
		};
	}

	public void init(FilterConfig config) throws ServletException {
	}

	protected boolean matches(HttpServletRequest request, String urlToMatch) {
		String uri = extractUri(request);
		String contextPath = prependContextPath(request, urlToMatch);
		return matcher.match(contextPath, uri);
	}

	private String prependContextPath(HttpServletRequest request, String urlToMatch) {
		if ("".equals(request.getContextPath())) {
			return urlToMatch;
		}
		return request.getContextPath() + urlToMatch;
	}

	private String extractUri(HttpServletRequest request) {

		String uri = request.getRequestURI();
		int pathParamIndex = uri.indexOf(';');

		if (pathParamIndex > 0) {
			// strip everything after the first semi-colon
			uri = uri.substring(0, pathParamIndex);
		}
		return uri;

	}

	/**
	 * @param authorizationEndpointUrl the authorizationEndpointUrl to set
	 */
	public void setAuthorizationEndpointUrl(String authorizationEndpointUrl) {
		this.authorizationEndpointUrl = authorizationEndpointUrl;
	}

	/**
	 * @param tokenEndpointUrl the tokenEndpointUrl to set
	 */
	public void setTokenEndpointUrl(String tokenEndpointUrl) {
		this.tokenEndpointUrl = tokenEndpointUrl;
	}
}
