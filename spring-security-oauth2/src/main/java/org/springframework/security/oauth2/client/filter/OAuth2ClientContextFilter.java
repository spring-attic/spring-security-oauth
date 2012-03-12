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
import org.springframework.security.oauth2.client.UserRedirectRequiredException;
import org.springframework.security.oauth2.client.context.OAuth2ClientContext;
import org.springframework.security.oauth2.client.context.OAuth2ClientContextHolder;
import org.springframework.security.oauth2.client.filter.cache.AccessTokenCache;
import org.springframework.security.oauth2.client.filter.cache.HttpSessionAccessTokenCache;
import org.springframework.security.oauth2.client.filter.state.HttpSessionStatePersistenceServices;
import org.springframework.security.oauth2.client.filter.state.StatePersistenceServices;
import org.springframework.security.oauth2.client.http.AccessTokenRequiredException;
import org.springframework.security.oauth2.client.resource.OAuth2AccessDeniedException;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.common.DefaultThrowableAnalyzer;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
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

	private AccessTokenCache tokenCache = new HttpSessionAccessTokenCache();

	private StatePersistenceServices statePersistenceServices = new HttpSessionStatePersistenceServices();

	private PortResolver portResolver = new PortResolverImpl();

	private ThrowableAnalyzer throwableAnalyzer = new DefaultThrowableAnalyzer();

	private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

	public void afterPropertiesSet() throws Exception {
		Assert.notNull(tokenCache, "TokenCacheServices must be supplied.");
		Assert.notNull(redirectStrategy, "A redirect strategy must be supplied.");
	}

	public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) servletRequest;
		HttpServletResponse response = (HttpServletResponse) servletResponse;
		// first set up the security context.

		@SuppressWarnings("unchecked")
		Map<String, String[]> parameters = (Map<String, String[]>) request.getParameterMap();
		AccessTokenRequest accessTokenRequest = new AccessTokenRequest(parameters);
		accessTokenRequest.setCurrentUri(calculateCurrentUri(request));
		String stateKey = request.getParameter("state");
		if (stateKey != null) {
			Object preservedState = statePersistenceServices.loadPreservedState(stateKey, request, response);
			// TODO: SECOAUTH-222 move this to the token provider
			if (preservedState == null) {
				throw new InvalidRequestException(
						"Possible CSRF detected - state parameter was present but no state could be found");
			}
			accessTokenRequest.setPreservedState(preservedState);
		}

		Map<String, OAuth2AccessToken> accessTokens = tokenCache.loadRememberedTokens(request, response);

		OAuth2ClientContext oauth2Context = new OAuth2ClientContext(accessTokens, accessTokenRequest);
		OAuth2ClientContextHolder.setContext(oauth2Context);

		try {
			chain.doFilter(servletRequest, servletResponse);

		} catch (IOException ex) {
			throw ex;
		} catch (Exception ex) {
			// Try to extract a SpringSecurityException from the stacktrace
			Throwable[] causeChain = throwableAnalyzer.determineCauseChain(ex);
			UserRedirectRequiredException redirect = (UserRedirectRequiredException) throwableAnalyzer
					.getFirstThrowableOfType(UserRedirectRequiredException.class, causeChain);
			if (redirect != null) {
				redirectUser(redirect, request, response);
			} else {
				if (ex instanceof ServletException) {
					throw (ServletException) ex;
				}
				if (ex instanceof RuntimeException) {
					throw (RuntimeException) ex;
				}
				throw new NestedServletException("Unhandled exception", ex);
			}
		} finally {
			OAuth2ClientContextHolder.clearContext();
			tokenCache.rememberTokens(oauth2Context.getNewAccessTokens(), request, response);
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
			} catch (UnsupportedEncodingException uee) {
				throw new IllegalStateException(uee);
			}
			appendChar = '&';
		}

		if (e.getStateKey() != null) {
			builder.append(appendChar).append("state").append('=').append(e.getStateKey());
			Object stateToPreserve = e.getStateToPreserve();
			if (stateToPreserve == null) {
				stateToPreserve = "state";
			}
			// TODO: SECOAUTH-96, save the request if a redirect URI is registered
			statePersistenceServices.preserveState(e.getStateKey(), stateToPreserve, request, response);
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
		} else {
			// Rethrow ServletExceptions and RuntimeExceptions as-is
			if (ex instanceof ServletException) {
				throw (ServletException) ex;
			}
			if (ex instanceof IOException) {
				throw (IOException) ex;
			} else if (ex instanceof RuntimeException) {
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
				} else {
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

	public void setClientTokenCache(AccessTokenCache tokenCache) {
		this.tokenCache = tokenCache;
	}

	public void setStatePersistenceServices(StatePersistenceServices stateServices) {
		this.statePersistenceServices = stateServices;
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
