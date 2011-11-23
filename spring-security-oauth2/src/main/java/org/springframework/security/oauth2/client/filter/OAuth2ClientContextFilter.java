package org.springframework.security.oauth2.client.filter;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
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
import org.springframework.security.oauth2.client.filter.flash.ClientTokenCache;
import org.springframework.security.oauth2.client.filter.flash.HttpSessionClientTokenCache;
import org.springframework.security.oauth2.client.filter.state.DefaultStateKeyGenerator;
import org.springframework.security.oauth2.client.filter.state.HttpSessionStatePersistenceServices;
import org.springframework.security.oauth2.client.filter.state.StateKeyGenerator;
import org.springframework.security.oauth2.client.filter.state.StatePersistenceServices;
import org.springframework.security.oauth2.client.http.AccessTokenRequiredException;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.AccessTokenProvider;
import org.springframework.security.oauth2.client.token.AccessTokenProviderChain;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeAccessTokenProvider;
import org.springframework.security.oauth2.common.DefaultThrowableAnalyzer;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.OAuth2AccessDeniedException;
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

	private ClientTokenCache tokenCache = new HttpSessionClientTokenCache();

	private StatePersistenceServices statePersistenceServices = new HttpSessionStatePersistenceServices();

	private StateKeyGenerator stateKeyGenerator = new DefaultStateKeyGenerator();

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
		OAuth2ClientContext oauth2Context = new OAuth2ClientContext();

		Map<String, OAuth2AccessToken> accessTokens = tokenCache.loadRememberedTokens(request, response);
		// Ensure session is created if necessary. TODO: find a better way to do this
		tokenCache.rememberTokens(accessTokens, request, response);
		accessTokens = accessTokens == null ? new HashMap<String, OAuth2AccessToken>()
				: new HashMap<String, OAuth2AccessToken>(accessTokens);
		oauth2Context.setAccessTokens(Collections.unmodifiableMap(accessTokens));

		OAuth2ClientContextHolder.setContext(oauth2Context);

		try {
			try {
				chain.doFilter(servletRequest, servletResponse);
			}
			catch (Exception ex) {

				OAuth2ProtectedResourceDetails resourceThatNeedsAuthorization = checkForResourceThatNeedsAuthorization(ex);
				String neededResourceId = resourceThatNeedsAuthorization.getId();
				accessTokens.remove(neededResourceId);

				@SuppressWarnings("unchecked")
				Map<String, String[]> parameters = (Map<String, String[]>) request.getParameterMap();
				AccessTokenRequest accessTokenRequest = new AccessTokenRequest(parameters);
				accessTokenRequest.setUserAuthorizationRedirectUri(calculateCurrentUri(request));
				accessTokenRequest.setPreservedState(statePersistenceServices.loadPreservedState(request.getParameter("state"),
						request, response));

				while (!accessTokens.containsKey(neededResourceId)) {
					OAuth2AccessToken accessToken;
					try {
						accessToken = accessTokenProvider.obtainNewAccessToken(resourceThatNeedsAuthorization,
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

					accessTokens.put(neededResourceId, accessToken);

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
					catch (Exception e1) {
						resourceThatNeedsAuthorization = checkForResourceThatNeedsAuthorization(e1);
						neededResourceId = resourceThatNeedsAuthorization.getId();
						accessTokens.remove(neededResourceId);
					}
				}
			}
		}
		finally {
			OAuth2ClientContextHolder.clearContext();
			tokenCache.rememberTokens(accessTokens, request, response);
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
	protected void redirectUser(OAuth2ProtectedResourceDetails resource, UserRedirectRequiredException e, HttpServletRequest request,
			HttpServletResponse response) throws IOException {
		if (e.getStateToPreserve() != null) {
			String key = stateKeyGenerator.generateKey(e.getStateKey(), resource);
			// TODO: SECOAUTH-96, save the request if a redirect URI is registered
			statePersistenceServices.preserveState(key, e.getStateToPreserve(), request, response);
		}

		try {
			String redirectUri = e.getRedirectUri();
			StringBuilder builder = new StringBuilder(redirectUri);
			Map<String, String> requestParams = e.getRequestParams();
			char appendChar = redirectUri.indexOf('?') < 0 ? '?' : '&';
			for (Map.Entry<String, String> param : requestParams.entrySet()) {
				builder.append(appendChar).append(param.getKey()).append('=')
						.append(URLEncoder.encode(param.getValue(), "UTF-8"));
				appendChar = '&';
			}

			request.setAttribute("org.springframework.security.oauth2.client.UserRedirectRequiredException", e);
			this.redirectStrategy.sendRedirect(request, response, builder.toString());
		}
		catch (UnsupportedEncodingException uee) {
			throw new IllegalStateException(uee);
		}
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

	public void setClientTokenCache(ClientTokenCache tokenCache) {
		this.tokenCache = tokenCache;
	}

	public void setStatePersistenceServices(StatePersistenceServices stateServices) {
		this.statePersistenceServices = stateServices;
	}
	
	public void setStateKeyGenerator(StateKeyGenerator stateKeyGenerator) {
		this.stateKeyGenerator = stateKeyGenerator;
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
