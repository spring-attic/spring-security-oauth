/*
 * Copyright 2008-2009 Web Cohesion
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.oauth.consumer.filter;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.oauth.common.OAuthProviderParameter;
import org.springframework.security.oauth.consumer.AccessTokenRequiredException;
import org.springframework.security.oauth.consumer.OAuthConsumerSupport;
import org.springframework.security.oauth.consumer.OAuthConsumerToken;
import org.springframework.security.oauth.consumer.OAuthRequestFailedException;
import org.springframework.security.oauth.consumer.OAuthSecurityContextHolder;
import org.springframework.security.oauth.consumer.OAuthSecurityContextImpl;
import org.springframework.security.oauth.consumer.ProtectedResourceDetails;
import org.springframework.security.oauth.consumer.rememberme.HttpSessionOAuthRememberMeServices;
import org.springframework.security.oauth.consumer.rememberme.OAuthRememberMeServices;
import org.springframework.security.oauth.consumer.token.HttpSessionBasedTokenServices;
import org.springframework.security.oauth.consumer.token.OAuthConsumerTokenServices;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.PortResolver;
import org.springframework.security.web.PortResolverImpl;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.security.web.util.ThrowableAnalyzer;
import org.springframework.security.web.util.ThrowableCauseExtractor;
import org.springframework.util.Assert;

/**
 * OAuth filter that establishes an OAuth security context.
 *
 * @author Ryan Heaton
 */
public class OAuthConsumerContextFilter implements Filter, InitializingBean, MessageSourceAware {

	public static final String ACCESS_TOKENS_DEFAULT_ATTRIBUTE = "OAUTH_ACCESS_TOKENS";
	public static final String OAUTH_FAILURE_KEY = "OAUTH_FAILURE_KEY";
	private static final Log LOG = LogFactory.getLog(OAuthConsumerContextFilter.class);

	private AccessDeniedHandler OAuthFailureHandler;
	protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
	private OAuthRememberMeServices rememberMeServices = new HttpSessionOAuthRememberMeServices();
	private OAuthConsumerSupport consumerSupport;
	private String accessTokensRequestAttribute = ACCESS_TOKENS_DEFAULT_ATTRIBUTE;
	private PortResolver portResolver = new PortResolverImpl();
	private ThrowableAnalyzer throwableAnalyzer = new DefaultThrowableAnalyzer();
	private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

	private OAuthConsumerTokenServices tokenServices = new HttpSessionBasedTokenServices();

	public void afterPropertiesSet() throws Exception {
		Assert.notNull(rememberMeServices, "Remember-me services must be provided.");
		Assert.notNull(consumerSupport, "Consumer support must be provided.");
		Assert.notNull(tokenServices, "OAuth token services are required.");
		Assert.notNull(redirectStrategy, "A redirect strategy must be supplied.");
	}

	public void init(FilterConfig ignored) throws ServletException {
	}

	public void destroy() {
	}

	public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain) throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) servletRequest;
		HttpServletResponse response = (HttpServletResponse) servletResponse;
		OAuthSecurityContextImpl context = new OAuthSecurityContextImpl();
		context.setDetails(request);

		Map<String, OAuthConsumerToken> rememberedTokens = getRememberMeServices().loadRememberedTokens(request, response);
		Map<String, OAuthConsumerToken> accessTokens = new TreeMap<String, OAuthConsumerToken>();
		Map<String, OAuthConsumerToken> requestTokens = new TreeMap<String, OAuthConsumerToken>();
		if (rememberedTokens != null) {
			for (Map.Entry<String, OAuthConsumerToken> tokenEntry : rememberedTokens.entrySet()) {
				OAuthConsumerToken token = tokenEntry.getValue();
				if (token != null) {
					if (token.isAccessToken()) {
						accessTokens.put(tokenEntry.getKey(), token);
					}
					else {
						requestTokens.put(tokenEntry.getKey(), token);
					}
				}
			}
		}

		context.setAccessTokens(accessTokens);
		OAuthSecurityContextHolder.setContext(context);
		if (LOG.isDebugEnabled()) {
			LOG.debug("Storing access tokens in request attribute '" + getAccessTokensRequestAttribute() + "'.");
		}

		try {
			try {
				request.setAttribute(getAccessTokensRequestAttribute(), new ArrayList<OAuthConsumerToken>(accessTokens.values()));
				chain.doFilter(request, response);
			}
			catch (Exception e) {
				try {
					ProtectedResourceDetails resourceThatNeedsAuthorization = checkForResourceThatNeedsAuthorization(e);
					String neededResourceId = resourceThatNeedsAuthorization.getId();
					while (!accessTokens.containsKey(neededResourceId)) {
						OAuthConsumerToken token = requestTokens.remove(neededResourceId);
						if (token == null) {
							token = getTokenServices().getToken(neededResourceId);
						}

						String verifier = request.getParameter(OAuthProviderParameter.oauth_verifier.toString());
						// if the token is null OR
						// if there is NO access token and (we're not using 1.0a or the verifier is not null)
						if (token == null || (!token.isAccessToken() && (!resourceThatNeedsAuthorization.isUse10a() || verifier == null))) {
							//no token associated with the resource, start the oauth flow.
							//if there's a request token, but no verifier, we'll assume that a previous oauth request failed and we need to get a new request token.
							if (LOG.isDebugEnabled()) {
								LOG.debug("Obtaining request token for resource: " + neededResourceId);
							}

							//obtain authorization.
							String callbackURL = response.encodeRedirectURL(getCallbackURL(request));
							token = getConsumerSupport().getUnauthorizedRequestToken(neededResourceId, callbackURL);
							if (LOG.isDebugEnabled()) {
								LOG.debug("Request token obtained for resource " + neededResourceId + ": " + token);
							}

							//okay, we've got a request token, now we need to authorize it.
							requestTokens.put(neededResourceId, token);
							getTokenServices().storeToken(neededResourceId, token);
							String redirect = getUserAuthorizationRedirectURL(resourceThatNeedsAuthorization, token, callbackURL);

							if (LOG.isDebugEnabled()) {
								LOG.debug("Redirecting request to " + redirect + " for user authorization of the request token for resource " + neededResourceId + ".");
							}

							request.setAttribute("org.springframework.security.oauth.consumer.AccessTokenRequiredException", e);
							this.redirectStrategy.sendRedirect(request, response, redirect);
							return;
						}
						else if (!token.isAccessToken()) {
							//we have a presumably authorized request token, let's try to get an access token with it.
							if (LOG.isDebugEnabled()) {
								LOG.debug("Obtaining access token for resource: " + neededResourceId);
							}

							//authorize the request token and store it.
							try {
								token = getConsumerSupport().getAccessToken(token, verifier);
							}
							finally {
								getTokenServices().removeToken(neededResourceId);
							}

							if (LOG.isDebugEnabled()) {
								LOG.debug("Access token " + token + " obtained for resource " + neededResourceId + ". Now storing and using.");
							}

							getTokenServices().storeToken(neededResourceId, token);
						}

						accessTokens.put(neededResourceId, token);

						try {
							//try again
							if (!response.isCommitted()) {
								request.setAttribute(getAccessTokensRequestAttribute(), new ArrayList<OAuthConsumerToken>(accessTokens.values()));
								chain.doFilter(request, response);
							}
							else {
								//dang. what do we do now?
								throw new IllegalStateException("Unable to reprocess filter chain with needed OAuth2 resources because the response is already committed.");
							}
						}
						catch (Exception e1) {
							resourceThatNeedsAuthorization = checkForResourceThatNeedsAuthorization(e1);
							neededResourceId = resourceThatNeedsAuthorization.getId();
						}
					}
				}
				catch (OAuthRequestFailedException eo) {
					fail(request, response, eo);
				}
				catch (Exception ex) {
					Throwable[] causeChain = getThrowableAnalyzer().determineCauseChain(ex);
					OAuthRequestFailedException rfe = (OAuthRequestFailedException) getThrowableAnalyzer().getFirstThrowableOfType(OAuthRequestFailedException.class, causeChain);
					if (rfe != null) {
						fail(request, response, rfe);
					}
					else {
						// Rethrow ServletExceptions and RuntimeExceptions as-is
						if (ex instanceof ServletException) {
							throw (ServletException) ex;
						}
						else if (ex instanceof RuntimeException) {
							throw (RuntimeException) ex;
						}

						// Wrap other Exceptions. These are not expected to happen
						throw new RuntimeException(ex);
					}
				}
			}
		}
		finally {
			OAuthSecurityContextHolder.setContext(null);
			HashMap<String, OAuthConsumerToken> tokensToRemember = new HashMap<String, OAuthConsumerToken>();
			tokensToRemember.putAll(requestTokens);
			tokensToRemember.putAll(accessTokens);
			getRememberMeServices().rememberTokens(tokensToRemember, request, response);
		}
	}

	/**
	 * Check the given exception for the resource that needs authorization. If the exception was not thrown because a resource needed authorization, then rethrow
	 * the exception.
	 *
	 * @param ex The exception.
	 * @return The resource that needed authorization (never null).
	 * @throws ServletException in the case of an underlying Servlet API exception
	 * @throws IOException in the case of general IO exceptions
	 */
	protected ProtectedResourceDetails checkForResourceThatNeedsAuthorization(Exception ex) throws ServletException, IOException {
		Throwable[] causeChain = getThrowableAnalyzer().determineCauseChain(ex);
		AccessTokenRequiredException ase = (AccessTokenRequiredException) getThrowableAnalyzer().getFirstThrowableOfType(AccessTokenRequiredException.class, causeChain);
		ProtectedResourceDetails resourceThatNeedsAuthorization;
		if (ase != null) {
			resourceThatNeedsAuthorization = ase.getResource();
			if (resourceThatNeedsAuthorization == null) {
				throw new OAuthRequestFailedException(ase.getMessage());
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
	 * Get the callback URL for the specified request.
	 *
	 * @param request The request.
	 * @return The callback URL.
	 */
	protected String getCallbackURL(HttpServletRequest request) {
		return new DefaultSavedRequest(request, getPortResolver()).getRedirectUrl();
	}

	/**
	 * Get the URL to which to redirect the user for authorization of protected resources.
	 *
	 * @param details	  The resource for which to get the authorization url.
	 * @param requestToken The request token.
	 * @param callbackURL  The callback URL.
	 * @return The URL.
	 */
	protected String getUserAuthorizationRedirectURL(ProtectedResourceDetails details, OAuthConsumerToken requestToken, String callbackURL) {
		try {
			String baseURL = details.getUserAuthorizationURL();
			StringBuilder builder = new StringBuilder(baseURL);
			char appendChar = baseURL.indexOf('?') < 0 ? '?' : '&';
			builder.append(appendChar).append("oauth_token=");
			builder.append(URLEncoder.encode(requestToken.getValue(), "UTF-8"));
			if (!details.isUse10a()) {
				builder.append('&').append("oauth_callback=");
				builder.append(URLEncoder.encode(callbackURL, "UTF-8"));
			}
			return builder.toString();
		}
		catch (UnsupportedEncodingException e) {
			throw new IllegalStateException(e);
		}
	}

	/**
	 * Common logic for OAuth failed. (Note that the default logic doesn't pass the failure through so as to not mess
	 * with the current authentication.)
	 *
	 * @param request  The request.
	 * @param response The response.
	 * @param failure  The failure.
	 * @throws ServletException in the case of an underlying Servlet API exception
	 * @throws IOException in the case of general IO exceptions
	 */
	protected void fail(HttpServletRequest request, HttpServletResponse response, OAuthRequestFailedException failure) throws IOException, ServletException {
		try {
			//attempt to set the last exception.
			request.getSession().setAttribute(OAUTH_FAILURE_KEY, failure);
		}
		catch (Exception e) {
			//fall through....
		}

		if (LOG.isDebugEnabled()) {
			LOG.debug(failure);
		}

		if (getOAuthFailureHandler() != null) {
			getOAuthFailureHandler().handle(request, response, failure);
		}
		else {
			throw failure;
		}
	}

	/**
	 * The oauth failure handler.
	 *
	 * @return The oauth failure handler.
	 */
	public AccessDeniedHandler getOAuthFailureHandler() {
		return OAuthFailureHandler;
	}

	/**
	 * The oauth failure handler.
	 *
	 * @param OAuthFailureHandler The oauth failure handler.
	 */
	public void setOAuthFailureHandler(AccessDeniedHandler OAuthFailureHandler) {
		this.OAuthFailureHandler = OAuthFailureHandler;
	}

	/**
	 * The token services.
	 *
	 * @return The token services.
	 */
	public OAuthConsumerTokenServices getTokenServices() {
		return tokenServices;
	}

	/**
	 * The token services.
	 *
	 * @param tokenServices The token services.
	 */
	public void setTokenServices(OAuthConsumerTokenServices tokenServices) {
		this.tokenServices = tokenServices;
	}

	/**
	 * Set the message source.
	 *
	 * @param messageSource The message source.
	 */
	public void setMessageSource(MessageSource messageSource) {
		this.messages = new MessageSourceAccessor(messageSource);
	}

	/**
	 * The OAuth consumer support.
	 *
	 * @return The OAuth consumer support.
	 */
	public OAuthConsumerSupport getConsumerSupport() {
		return consumerSupport;
	}

	/**
	 * The OAuth consumer support.
	 *
	 * @param consumerSupport The OAuth consumer support.
	 */
	public void setConsumerSupport(OAuthConsumerSupport consumerSupport) {
		this.consumerSupport = consumerSupport;
	}

	/**
	 * The default request attribute into which the OAuth access tokens are stored.
	 *
	 * @return The default request attribute into which the OAuth access tokens are stored.
	 */
	public String getAccessTokensRequestAttribute() {
		return accessTokensRequestAttribute;
	}

	/**
	 * The default request attribute into which the OAuth access tokens are stored.
	 *
	 * @param accessTokensRequestAttribute The default request attribute into which the OAuth access tokens are stored.
	 */
	public void setAccessTokensRequestAttribute(String accessTokensRequestAttribute) {
		this.accessTokensRequestAttribute = accessTokensRequestAttribute;
	}

	/**
	 * The port resolver.
	 *
	 * @return The port resolver.
	 */
	public PortResolver getPortResolver() {
		return portResolver;
	}

	/**
	 * The port resolver.
	 *
	 * @param portResolver The port resolver.
	 */
	public void setPortResolver(PortResolver portResolver) {
		this.portResolver = portResolver;
	}

	/**
	 * The remember-me services.
	 *
	 * @return The remember-me services.
	 */
	public OAuthRememberMeServices getRememberMeServices() {
		return rememberMeServices;
	}

	/**
	 * The remember-me services.
	 *
	 * @param rememberMeServices The remember-me services.
	 */
	public void setRememberMeServices(OAuthRememberMeServices rememberMeServices) {
		this.rememberMeServices = rememberMeServices;
	}

	/**
	 * The throwable analyzer.
	 *
	 * @return The throwable analyzer.
	 */
	public ThrowableAnalyzer getThrowableAnalyzer() {
		return throwableAnalyzer;
	}

	/**
	 * The throwable analyzer.
	 *
	 * @param throwableAnalyzer The throwable analyzer.
	 */
	public void setThrowableAnalyzer(ThrowableAnalyzer throwableAnalyzer) {
		this.throwableAnalyzer = throwableAnalyzer;
	}

	/**
	 * The redirect strategy.
	 *
	 * @return The redirect strategy.
	 */
	public RedirectStrategy getRedirectStrategy() {
		return redirectStrategy;
	}

	/**
	 * The redirect strategy.
	 *
	 * @param redirectStrategy The redirect strategy.
	 */
	public void setRedirectStrategy(RedirectStrategy redirectStrategy) {
		this.redirectStrategy = redirectStrategy;
	}

	/**
	 * Default implementation of <code>ThrowableAnalyzer</code> which is capable of also unwrapping
	 * <code>ServletException</code>s.
	 */
	private static final class DefaultThrowableAnalyzer extends ThrowableAnalyzer {
		/**
		 * @see org.springframework.security.web.util.ThrowableAnalyzer#initExtractorMap()
		 */
		protected void initExtractorMap() {
			super.initExtractorMap();

			registerExtractor(ServletException.class, new ThrowableCauseExtractor() {
				public Throwable extractCause(Throwable throwable) {
					ThrowableAnalyzer.verifyThrowableHierarchy(throwable, ServletException.class);
					return ((ServletException) throwable).getRootCause();
				}
			});
		}
	}
}
