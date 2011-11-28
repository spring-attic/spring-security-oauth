package org.springframework.security.oauth2.client.filter;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Arrays;
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
import org.springframework.security.oauth2.client.token.AccessTokenProvider;
import org.springframework.security.oauth2.client.token.AccessTokenProviderChain;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeAccessTokenProvider;
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

/**
 * Security filter for an OAuth2 client.
 * 
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class OAuth2ClientContextFilter implements Filter, InitializingBean {

	private AccessTokenProvider accessTokenProvider = new AccessTokenProviderChain(Arrays.<AccessTokenProvider> asList(
			new AuthorizationCodeAccessTokenProvider(), new ClientCredentialsAccessTokenProvider()));

	private AccessTokenCache tokenCache = new HttpSessionAccessTokenCache();

	private StatePersistenceServices statePersistenceServices = new HttpSessionStatePersistenceServices();

	private PortResolver portResolver = new PortResolverImpl();

	private ThrowableAnalyzer throwableAnalyzer = new DefaultThrowableAnalyzer();

	private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

	private boolean redirectOnError = false;

	public void afterPropertiesSet() throws Exception {
		Assert.notNull(accessTokenProvider, "An OAuth2 access token provider must be supplied.");
		Assert.notNull(tokenCache, "TokenCacheServices must be supplied.");
		Assert.notNull(redirectStrategy, "A redirect strategy must be supplied.");
	}

	public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) servletRequest;
		HttpServletResponse response = (HttpServletResponse) servletResponse;
		// first set up the security context.

		Map<String, OAuth2AccessToken> accessTokens = tokenCache.loadRememberedTokens(request, response);

		OAuth2ClientContext oauth2Context = new OAuth2ClientContext(accessTokens);
		OAuth2ClientContextHolder.setContext(oauth2Context);

		try {
			try {
				chain.doFilter(servletRequest, servletResponse);
			}
			catch (Exception ex) {

				OAuth2ProtectedResourceDetails resourceThatNeedsAuthorization = checkForResourceThatNeedsAuthorization(ex);
				oauth2Context.removeAccessToken(resourceThatNeedsAuthorization);

				@SuppressWarnings("unchecked")
				Map<String, String[]> parameters = (Map<String, String[]>) request.getParameterMap();
				AccessTokenRequest accessTokenRequest = new AccessTokenRequest(parameters);
				accessTokenRequest.setUserAuthorizationRedirectUri(calculateCurrentUri(request));
				String stateKey = request.getParameter("state");
				if (stateKey != null) {
					Object preservedState = statePersistenceServices.loadPreservedState(stateKey, request,
							response);
					if (preservedState==null) {
						throw new InvalidRequestException("Possible CSRF detected - state parameter was present but no state could be found");
					}
					accessTokenRequest.setPreservedState(preservedState);
				}

				// While loop handles case that multiple resources are needed in the same request
				while (!oauth2Context.containsResource(resourceThatNeedsAuthorization)) {

					OAuth2AccessToken existingToken = oauth2Context.getAccessToken(resourceThatNeedsAuthorization);
					if (existingToken != null) {
						accessTokenRequest.setExistingToken(existingToken);
					}

					OAuth2AccessToken accessToken;
					try {
						accessToken = accessTokenProvider.obtainAccessToken(resourceThatNeedsAuthorization,
								accessTokenRequest);
						if (accessToken == null) {
							throw new IllegalStateException(
									"Access token manager returned a null access token, which is illegal according to the contract.");
						}
					}
					catch (UserRedirectRequiredException e) {
						redirectUser(resourceThatNeedsAuthorization, e, request, response);
						return;
					}

					oauth2Context.addAccessToken(resourceThatNeedsAuthorization, accessToken);

					try {
						// try again
						if (!response.isCommitted() && !this.redirectOnError) {
							chain.doFilter(request, response);
						}
						else {
							// Dang. what do we do now? Best we can do is redirect.
							String redirect = request.getServletPath();
							if (request.getQueryString() != null) {
								redirect += "?" + request.getQueryString();
							}
							this.redirectStrategy.sendRedirect(request, response, redirect);
						}
					}
					catch (Exception e) {
						resourceThatNeedsAuthorization = checkForResourceThatNeedsAuthorization(e);
						oauth2Context.removeAccessToken(resourceThatNeedsAuthorization);
					}

				}
			}
		}
		finally {
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
	protected void redirectUser(OAuth2ProtectedResourceDetails resource, UserRedirectRequiredException e,
			HttpServletRequest request, HttpServletResponse response) throws IOException {

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

	public void setAccessTokenProvider(AccessTokenProvider accessTokenProvider) {
		this.accessTokenProvider = accessTokenProvider;
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

	/**
	 * Flag to indicate that instead of executing the filter chain again, the filter should send a redirect to have the
	 * request repeated. Defaults to false, but users of some app server platforms (e.g. Weblogic) might find that they
	 * need this switched on to avoid problems with executing the filter chain more than once in the same request.
	 * 
	 * @param redirectOnError the flag to set (default false)
	 */
	public void setRedirectOnError(boolean redirectOnError) {
		this.redirectOnError = redirectOnError;
	}
}
