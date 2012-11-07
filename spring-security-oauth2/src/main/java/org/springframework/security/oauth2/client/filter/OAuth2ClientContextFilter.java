package org.springframework.security.oauth2.client.filter;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Enumeration;
import java.util.Map;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.oauth2.client.http.AccessTokenRequiredException;
import org.springframework.security.oauth2.client.resource.OAuth2AccessDeniedException;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.resource.UserRedirectRequiredException;
import org.springframework.security.oauth2.common.DefaultThrowableAnalyzer;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.PortResolver;
import org.springframework.security.web.PortResolverImpl;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.util.ThrowableAnalyzer;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.Assert;
import org.springframework.web.util.NestedServletException;

/**
 * Security filter for an OAuth2 client.
 * 
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class OAuth2ClientContextFilter implements Filter, InitializingBean {

	/**
	 * Key in request attributes for the current URI in case it is needed by rest client code that needs to send a
	 * redirect URI to an authorization server.
	 */
	public static final String CURRENT_URI = "currentUri";

	private PortResolver portResolver = new PortResolverImpl();

	private ThrowableAnalyzer throwableAnalyzer = new DefaultThrowableAnalyzer();

	private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

	public void afterPropertiesSet() throws Exception {
		Assert.notNull(redirectStrategy, "A redirect strategy must be supplied.");
	}

	public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) servletRequest;
		HttpServletResponse response = (HttpServletResponse) servletResponse;
		request.setAttribute(CURRENT_URI, calculateCurrentUri(request));

		try {
			chain.doFilter(servletRequest, servletResponse);
		}
		catch (IOException ex) {
			throw ex;
		}
		catch (Exception ex) {
			// Try to extract a SpringSecurityException from the stacktrace
			Throwable[] causeChain = throwableAnalyzer.determineCauseChain(ex);
			UserRedirectRequiredException redirect = (UserRedirectRequiredException) throwableAnalyzer
					.getFirstThrowableOfType(UserRedirectRequiredException.class, causeChain);
			if (redirect != null) {
				redirectUser(redirect, request, response);
			}
			else {
				if (ex instanceof ServletException) {
					throw (ServletException) ex;
				}
				if (ex instanceof RuntimeException) {
					throw (RuntimeException) ex;
				}
				throw new NestedServletException("Unhandled exception", ex);
			}
		}
	}

	/**
	 * Redirect the user according to the specified exception.
	 * 
	 * @param resourceThatNeedsAuthorization
	 * @param e The user redirect exception.
	 * @param request The request.
	 * @param response The response.
	 */
	protected void redirectUser(UserRedirectRequiredException e, HttpServletRequest request,
			HttpServletResponse response) throws IOException {

		String redirectUri = e.getRedirectUri();
		StringBuilder builder = new StringBuilder(redirectUri);
		Map<String, String> requestParams = e.getRequestParams();
		char appendChar = redirectUri.indexOf('?') < 0 ? '?' : '&';
		for (Map.Entry<String, String> param : requestParams.entrySet()) {
			try {
				builder.append(appendChar).append(param.getKey()).append('=')
						.append(URLEncoder.encode(param.getValue(), "UTF-8"));
			}
			catch (UnsupportedEncodingException uee) {
				throw new IllegalStateException(uee);
			}
			appendChar = '&';
		}

		if (e.getStateKey() != null) {
			builder.append(appendChar).append("state").append('=').append(e.getStateKey());
		}

		this.redirectStrategy.sendRedirect(request, response, builder.toString());

	}

	/**
	 * Check the given exception for the resource that needs authorization. If the exception was not thrown because a
	 * resource needed authorization, then rethrow the exception.
	 * 
	 * @param ex The exception.
	 * @return The resource that needed authorization (never null).
	 */
	protected OAuth2ProtectedResourceDetails checkForResourceThatNeedsAuthorization(Exception ex)
			throws ServletException, IOException {
		Throwable[] causeChain = throwableAnalyzer.determineCauseChain(ex);
		AccessTokenRequiredException ase = (AccessTokenRequiredException) throwableAnalyzer.getFirstThrowableOfType(
				AccessTokenRequiredException.class, causeChain);
		OAuth2ProtectedResourceDetails resourceThatNeedsAuthorization;
		if (ase != null) {
			resourceThatNeedsAuthorization = ase.getResource();
			if (resourceThatNeedsAuthorization == null) {
				throw new OAuth2AccessDeniedException(ase.getMessage());
			}
		}
		else {
			// Rethrow ServletExceptions and RuntimeExceptions as-is
			if (ex instanceof ServletException) {
				throw (ServletException) ex;
			}
			if (ex instanceof IOException) {
				throw (IOException) ex;
			}
			else if (ex instanceof RuntimeException) {
				throw (RuntimeException) ex;
			}

			// Wrap other Exceptions. These are not expected to happen
			throw new RuntimeException(ex);
		}
		return resourceThatNeedsAuthorization;
	}

	/**
	 * Calculate the current URI given the request.
	 * 
	 * @param request The request.
	 * @return The current uri.
	 */
	protected String calculateCurrentUri(HttpServletRequest request) throws UnsupportedEncodingException {
		StringBuilder queryBuilder = new StringBuilder();
		@SuppressWarnings("unchecked")
		Enumeration<String> paramNames = request.getParameterNames();
		while (paramNames.hasMoreElements()) {
			String name = (String) paramNames.nextElement();
			if (!"code".equals(name)) {
				String[] parameterValues = request.getParameterValues(name);
				if (parameterValues.length == 0) {
					queryBuilder.append(URLEncoder.encode(name, "UTF-8"));
				}
				else {
					for (int i = 0; i < parameterValues.length; i++) {
						String parameterValue = parameterValues[i];
						queryBuilder.append(URLEncoder.encode(name, "UTF-8")).append('=')
								.append(URLEncoder.encode(parameterValue, "UTF-8"));
						if (i + 1 < parameterValues.length) {
							queryBuilder.append('&');
						}
					}
				}
			}

			if (paramNames.hasMoreElements() && queryBuilder.length() > 0) {
				queryBuilder.append('&');
			}
		}

		return UrlUtils.buildFullRequestUrl(request.getScheme(), request.getServerName(),
				portResolver.getServerPort(request), request.getRequestURI(),
				queryBuilder.length() > 0 ? queryBuilder.toString() : null);
	}

	public void init(FilterConfig filterConfig) throws ServletException {
	}

	public void destroy() {
	}

	public void setThrowableAnalyzer(ThrowableAnalyzer throwableAnalyzer) {
		this.throwableAnalyzer = throwableAnalyzer;
	}

	public void setPortResolver(PortResolver portResolver) {
		this.portResolver = portResolver;
	}

	public void setRedirectStrategy(RedirectStrategy redirectStrategy) {
		this.redirectStrategy = redirectStrategy;
	}

}
