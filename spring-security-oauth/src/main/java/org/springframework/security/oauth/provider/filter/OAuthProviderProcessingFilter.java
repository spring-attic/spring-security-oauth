/*
 * Copyright 2006-2014 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.springframework.security.oauth.provider.filter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth.common.OAuthConstants;
import org.springframework.security.oauth.common.OAuthException;
import org.springframework.security.oauth.common.OAuthParameters;
import org.springframework.security.oauth.common.signature.*;
import org.springframework.security.oauth.provider.*;
import org.springframework.security.oauth.provider.endpoint.FrameworkEndpointHandlerMapping;
import org.springframework.security.oauth.provider.nonce.ExpiringTimestampNonceServices;
import org.springframework.security.oauth.provider.nonce.OAuthNonceServices;
import org.springframework.security.oauth.provider.token.OAuthAccessProviderToken;
import org.springframework.security.oauth.provider.token.OAuthProviderToken;
import org.springframework.security.oauth.provider.token.OAuthProviderTokenServices;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Set;

/**
 * OAuth processing filter. Processes OAuth parameters and loads consumer authentication in the SecurityContext
 * for all requests: for protected resources and for the endpoints.
 * This filter then attempts to load the user authentication into the security context using a presented access token.
 * By default this filter allows the request to continue even if OAuth credentials are not presented
 * (allowing another filter to potentially load a different authentication request into the security context).
 * If the protected resource is available ONLY via OAuth access token,
 * set <code>ignoreMissingCredentials</code> to <code>false</code>.
 *
 * @author Ryan Heaton
 * @author <a rel="author" href="http://autayeu.com/">Aliaksandr Autayeu</a>
 */
public class OAuthProviderProcessingFilter extends OncePerRequestFilter implements MessageSourceAware {

	// for most framework end points credentials are required and cannot be skipped,
	// but for resources we're going to ignore missing credentials by default.
	// This is to allow a chance for the resource
	// to be accessed by some other means of authentication.
	private boolean ignoreMissingCredentials = true;

	private OAuthProcessingFilterEntryPoint authenticationEntryPoint = new OAuthProcessingFilterEntryPoint();
	private MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
	private OAuthProviderSupport providerSupport = new CoreOAuthProviderSupport();
	private OAuthSignatureMethodFactory signatureMethodFactory = new CoreOAuthSignatureMethodFactory();
	private OAuthNonceServices nonceServices = new ExpiringTimestampNonceServices();
	private OAuthAuthenticationHandler authHandler = new DefaultAuthenticationHandler();

	private OAuthProviderTokenServices tokenServices;
	private ConsumerDetailsService consumerDetailsService;
	private FrameworkEndpointHandlerMapping frameworkEndpointHandlerMapping;
	private String[] frameworkEndpoints = null;
	private String[] oauthAuthenticatedFrameworkEndpoints = null;

	@Override
	public void afterPropertiesSet() throws ServletException {
		super.afterPropertiesSet();
		Assert.notNull(consumerDetailsService, "A consumer details service is required.");
		Assert.notNull(tokenServices, "Token services are required.");
	}

	@Override
	public void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
		if (requiresAuthentication(request, response, chain)) {
			try {
				OAuthParameters oauthParams = getProviderSupport().parseParameters(request);
				if (parametersAreAdequate(oauthParams)) {
					if (logger.isDebugEnabled()) {
						logger.debug("OAuth parameters parsed: " + oauthParams.toString());
					}

					String consumerKey = oauthParams.getConsumerKey();
					if (consumerKey == null) {
						throw new InvalidOAuthParametersException(messages.getMessage("OAuthProviderProcessingFilter.missingConsumerKey", "Missing consumer key."));
					}

					// load the consumer details.
					ConsumerDetails consumerDetails = getConsumerDetailsService().loadConsumerByConsumerKey(consumerKey);
					if (logger.isDebugEnabled()) {
						logger.debug("Consumer details loaded for " + consumerKey + ": " + consumerDetails);
					}

					// validate the parameters for the consumer.
					validateOAuthParams(consumerDetails, oauthParams);
					if (logger.isDebugEnabled()) {
						logger.debug("Parameters validated.");
					}

					// extract the credentials.
					ConsumerCredentials credentials =
							new ConsumerCredentials(consumerKey,
													oauthParams.getSignature(),
													oauthParams.getSignatureMethod(),
													getProviderSupport().getSignatureBaseString(request),
													oauthParams.getToken());

					// create an authentication request.
					ConsumerAuthentication authentication = new ConsumerAuthentication(consumerDetails, credentials, oauthParams);
					authentication.setDetails(createDetails(request, consumerDetails));

					SecurityContext previousContext = SecurityContextHolder.getContext();
					try {
						// clear the context to establish a new one for OAuth
						// this enables the context to be used elsewhere (e.g. outside of current thread context)
						SecurityContextHolder.clearContext();
						// set the authentication request (unauthenticated) into a new context.
						SecurityContextHolder.getContext().setAuthentication(authentication);

						// validate the signature.
						validateSignature(authentication);

						// mark the authentication request as validated.
						authentication.setSignatureValidated(true);

						if (logger.isDebugEnabled()) {
							logger.debug("Signature validated.");
						}

						// for resource requests load user authentication from access token
						if (!isEndpointRequest(request)) {
							String token = authentication.getConsumerCredentials().getToken();
							OAuthAccessProviderToken accessToken = null;
							if (StringUtils.hasText(token)) {
								OAuthProviderToken authToken = getTokenServices().getToken(token);
								if (authToken == null) {
									throw new AccessDeniedException("Invalid access token.");
								}
								else if (!authToken.isAccessToken()) {
									throw new AccessDeniedException("Token should be an access token.");
								}
								else if (authToken instanceof OAuthAccessProviderToken) {
									accessToken = (OAuthAccessProviderToken) authToken;
								}
							}
							else if ((!(authentication.getConsumerDetails() instanceof ExtraTrustConsumerDetails)) ||
									((ExtraTrustConsumerDetails) authentication.getConsumerDetails()).isRequiredToObtainAuthenticatedToken()) {
								throw new InvalidOAuthParametersException(messages.getMessage("OAuthProviderProcessingFilter.missingToken", "Missing auth token."));
							}

							Authentication userAuthentication = authHandler.createAuthentication(request, authentication, accessToken);
							SecurityContextHolder.getContext().setAuthentication(userAuthentication);
						}

						chain.doFilter(request, response);
					}
					finally {
						//clear out the authentication to make sure it doesn't get cached.
						resetPreviousContext(previousContext);
					}
				}
				else if (!isIgnoreMissingCredentials() || isOAuthAuthenticatedEndpointRequest(request)) {
					throw new InvalidOAuthParametersException(messages.getMessage("OAuthProviderProcessingFilter.missingCredentials", "Inadequate OAuth consumer credentials."));
				}
				else {
					if (logger.isDebugEnabled()) {
						logger.debug("Supplied OAuth parameters are inadequate. Ignoring.");
					}
					chain.doFilter(request, response);
				}
			}
			catch (AuthenticationException ae) {
				fail(request, response, ae);
			}
			catch (ServletException e) {
				if (e.getRootCause() instanceof AuthenticationException) {
					fail(request, response, (AuthenticationException) e.getRootCause());
				}
				else {
					throw e;
				}
			}
		}
		else {
			if (logger.isDebugEnabled()) {
				logger.debug("Request does not require authentication.  OAuth processing skipped.");
			}

			chain.doFilter(request, response);
		}
	}

	/**
	 * Whether the request is a framework endpoint request (request token, access token, authorize token).
	 *
	 * @param request a request
	 * @return Whether the request is a framework endpoint request (request token, access token, authorize token)
	 */
	protected boolean isEndpointRequest(HttpServletRequest request) {
		boolean match = false;
		// for 2-legged endpoints might not be needed, so all requests are resource requests
		if (null != frameworkEndpointHandlerMapping) {
			if (null == frameworkEndpoints) {
				frameworkEndpoints = initEndpointPaths(frameworkEndpointHandlerMapping.getPaths());
			}

			match = matchesPath(request, frameworkEndpoints);

			if (logger.isDebugEnabled()) {
				logger.debug(request.getRequestURI() + " is an endpoint: " + match);
			}
		}
		return match;
	}

	/**
	 * Whether the request is an OAuth-authenticated framework endpoint request (request token, access token).
	 *
	 * @param request a request
	 * @return Whether the request is an OAuth-authenticated framework endpoint request (request token, access token)
	 */
	protected boolean isOAuthAuthenticatedEndpointRequest(HttpServletRequest request) {
		boolean match = false;
		// for 2-legged endpoints might not be needed, so all requests are resource requests
		if (null != frameworkEndpointHandlerMapping) {
			if (null == oauthAuthenticatedFrameworkEndpoints) {
				oauthAuthenticatedFrameworkEndpoints = initEndpointPaths(frameworkEndpointHandlerMapping.getOAuthAuthenticatedPaths());
			}

			match = matchesPath(request, oauthAuthenticatedFrameworkEndpoints);

			if (logger.isDebugEnabled()) {
				logger.debug(request.getRequestURI() + " is an authenticated endpoint: " + match);
			}
		}
		return match;
	}

	/**
	 * Converts a set of default framework end point paths to an array of actual paths.
	 *
	 * @param paths a set of default framework end point paths
	 * @return array of actual paths
	 */
	private String[] initEndpointPaths(Set<String> paths) {
		String[] result = new String[paths.size()];
		int i = 0;
		for (String defaultPath : paths) {
			result[i] = frameworkEndpointHandlerMapping.getPath(defaultPath);
			i++;
		}
		return result;
	}

	/**
	 * Returns true if a request matches a path in paths.
	 *
	 * @param request a request to match
	 * @param paths   a set of target path
	 * @return true if a request matches a path in paths
	 */
	private boolean matchesPath(HttpServletRequest request, String[] paths) {
		//based on org.springframework.security.ui.AbstractProcessingFilter.requiresAuthentication
		String uri = request.getRequestURI();
		int pathParamIndex = uri.indexOf(';');

		if (pathParamIndex > 0) {
			// strip everything after the first semi-colon
			uri = uri.substring(0, pathParamIndex);
		}

		boolean result = false;
		if ("".equals(request.getContextPath())) {
			for (String path : paths) {
				result = uri.endsWith(path);
				if (result) {
					break;
				}
			}
		}
		else {
			for (String path : paths) {
				result = uri.endsWith(request.getContextPath() + path);
				if (result) {
					break;
				}
			}
		}
		return result;
	}

	/**
	 * By default, OAuth parameters are adequate if a consumer key is present.
	 *
	 * @param oauthParams The oauth params.
	 * @return Whether the parsed parameters are adequate.
	 */
	protected boolean parametersAreAdequate(OAuthParameters oauthParams) {
		return null != oauthParams.getConsumerKey();
	}

	protected void resetPreviousContext(SecurityContext previousContext) {
		SecurityContextHolder.setContext(previousContext);
	}

	/**
	 * Create the details for the authentication request.
	 *
	 * @param request         The request.
	 * @param consumerDetails The consumer details.
	 * @return The authentication details.
	 */
	protected Object createDetails(HttpServletRequest request, ConsumerDetails consumerDetails) {
		return new OAuthAuthenticationDetails(request, consumerDetails);
	}

	/**
	 * Validate the signature of the request given the authentication request.
	 *
	 * @param authentication The authentication request.
	 */
	protected void validateSignature(ConsumerAuthentication authentication) throws AuthenticationException {
		SignatureSecret secret = authentication.getConsumerDetails().getSignatureSecret();
		String token = authentication.getConsumerCredentials().getToken();
		OAuthProviderToken authToken = null;
		if (token != null && !"".equals(token)) {
			authToken = getTokenServices().getToken(token);
		}

		String signatureMethod = authentication.getConsumerCredentials().getSignatureMethod();
		OAuthSignatureMethod method;
		try {
			method = getSignatureMethodFactory().getSignatureMethod(signatureMethod, secret, authToken != null ? authToken.getSecret() : null);
		}
		catch (UnsupportedSignatureMethodException e) {
			throw new OAuthException(e.getMessage(), e);
		}

		String signatureBaseString = authentication.getConsumerCredentials().getSignatureBaseString();
		String signature = authentication.getConsumerCredentials().getSignature();
		if (logger.isDebugEnabled()) {
			logger.debug("Verifying signature " + signature + " for signature base string " + signatureBaseString + " with method " + method.getName() + ".");
		}
		method.verify(signatureBaseString, signature);
	}

	/**
	 * Validates the OAuth parameters for the given consumer. Base implementation validates only those parameters
	 * that are required for all OAuth requests. This includes the nonce and timestamp, but not the signature.
	 *
	 * @param consumerDetails The consumer details.
	 * @param oauthParams     The OAuth parameters to validate.
	 * @throws InvalidOAuthParametersException If the OAuth parameters are invalid.
	 */
	protected void validateOAuthParams(ConsumerDetails consumerDetails, OAuthParameters oauthParams) throws InvalidOAuthParametersException {
		String version = oauthParams.getVersion();
		if ((version != null) && (!OAuthConstants.OAUTH_VERSION.equals(version))) {
			throw new OAuthVersionUnsupportedException("Unsupported OAuth version: " + version);
		}

		String realm = oauthParams.getRealm();
		realm = realm == null || "".equals(realm) ? null : realm;
		if ((realm != null) && (!realm.equals(this.authenticationEntryPoint.getRealmName()))) {
			throw new InvalidOAuthParametersException(messages.getMessage("OAuthProviderProcessingFilter.incorrectRealm",
																		  new Object[]{realm, this.getAuthenticationEntryPoint().getRealmName()},
																		  "Response realm name '{0}' does not match system realm name of '{1}'"));
		}

		if (null == oauthParams.getSignatureMethod()) {
			throw new InvalidOAuthParametersException(messages.getMessage("OAuthProviderProcessingFilter.missingSignatureMethod", "Missing signature method."));
		}

		if (null == oauthParams.getSignature()) {
			throw new InvalidOAuthParametersException(messages.getMessage("OAuthProviderProcessingFilter.missingSignature", "Missing signature."));
		}

		if (null == oauthParams.getTimestamp()) {
			throw new InvalidOAuthParametersException(messages.getMessage("OAuthProviderProcessingFilter.missingTimestamp", "Missing timestamp."));
		}

		String nonce = oauthParams.getNonce();
		if (null == nonce) {
			throw new InvalidOAuthParametersException(messages.getMessage("OAuthProviderProcessingFilter.missingNonce", "Missing nonce."));
		}

		String timestamp = oauthParams.getTimestamp();
		try {
			getNonceServices().validateNonce(consumerDetails, Long.parseLong(timestamp), nonce);
		}
		catch (NumberFormatException e) {
			throw new InvalidOAuthParametersException(messages.getMessage("OAuthProviderProcessingFilter.invalidTimestamp", new Object[]{timestamp}, "Timestamp must be a positive integer. Invalid value: {0}"));
		}

		validateAdditionalParameters(consumerDetails, oauthParams);
	}

	/**
	 * Do any additional validation checks for the specified oauth params.  Default implementation is a no-op.
	 *
	 * @param consumerDetails The consumer details.
	 * @param oauthParams     The params.
	 */
	protected void validateAdditionalParameters(ConsumerDetails consumerDetails, OAuthParameters oauthParams) {
		// no-op
	}

	/**
	 * Common logic for OAuth failed.
	 *
	 * @param request  The request.
	 * @param response The response.
	 * @param failure  The failure.
	 */
	protected void fail(HttpServletRequest request, HttpServletResponse response, AuthenticationException failure) throws IOException, ServletException {
		SecurityContextHolder.clearContext();

		if (logger.isDebugEnabled()) {
			logger.debug(failure);
		}

		authenticationEntryPoint.commence(request, response, failure);
	}

	/**
	 * Whether this filter is configured to process the specified request.
	 *
	 * @param request     The request.
	 * @param response    The response
	 * @param filterChain The filter chain
	 * @return Whether this filter is configured to process the specified request.
	 */
	protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) {
		return true;
	}

	/**
	 * The authentication entry point.
	 *
	 * @return The authentication entry point.
	 */
	public OAuthProcessingFilterEntryPoint getAuthenticationEntryPoint() {
		return authenticationEntryPoint;
	}

	/**
	 * The authentication entry point.
	 *
	 * @param authenticationEntryPoint The authentication entry point.
	 */
	@Autowired ( required = false )
	public void setAuthenticationEntryPoint(OAuthProcessingFilterEntryPoint authenticationEntryPoint) {
		this.authenticationEntryPoint = authenticationEntryPoint;
	}

	/**
	 * The consumer details service.
	 *
	 * @return The consumer details service.
	 */
	public ConsumerDetailsService getConsumerDetailsService() {
		return consumerDetailsService;
	}

	/**
	 * The consumer details service.
	 *
	 * @param consumerDetailsService The consumer details service.
	 */
	@Autowired
	public void setConsumerDetailsService(ConsumerDetailsService consumerDetailsService) {
		this.consumerDetailsService = consumerDetailsService;
	}

	/**
	 * The nonce services.
	 *
	 * @return The nonce services.
	 */
	public OAuthNonceServices getNonceServices() {
		return nonceServices;
	}

	/**
	 * The nonce services.
	 *
	 * @param nonceServices The nonce services.
	 */
	@Autowired ( required = false )
	public void setNonceServices(OAuthNonceServices nonceServices) {
		this.nonceServices = nonceServices;
	}

	/**
	 * Get the OAuth token services.
	 *
	 * @return The OAuth token services.
	 */
	public OAuthProviderTokenServices getTokenServices() {
		return tokenServices;
	}

	/**
	 * The OAuth token services.
	 *
	 * @param tokenServices The OAuth token services.
	 */
	@Autowired
	public void setTokenServices(OAuthProviderTokenServices tokenServices) {
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
	 * The OAuth provider support.
	 *
	 * @return The OAuth provider support.
	 */
	public OAuthProviderSupport getProviderSupport() {
		return providerSupport;
	}

	/**
	 * The OAuth provider support.
	 *
	 * @param providerSupport The OAuth provider support.
	 */
	@Autowired ( required = false )
	public void setProviderSupport(OAuthProviderSupport providerSupport) {
		this.providerSupport = providerSupport;
	}

	/**
	 * The OAuth signature method factory.
	 *
	 * @return The OAuth signature method factory.
	 */
	public OAuthSignatureMethodFactory getSignatureMethodFactory() {
		return signatureMethodFactory;
	}

	/**
	 * The OAuth signature method factory.
	 *
	 * @param signatureMethodFactory The OAuth signature method factory.
	 */
	@Autowired ( required = false )
	public void setSignatureMethodFactory(OAuthSignatureMethodFactory signatureMethodFactory) {
		this.signatureMethodFactory = signatureMethodFactory;
	}

	/**
	 * Whether to ignore missing OAuth credentials.
	 *
	 * @return Whether to ignore missing OAuth credentials.
	 */
	public boolean isIgnoreMissingCredentials() {
		return ignoreMissingCredentials;
	}

	/**
	 * Whether to ignore missing OAuth credentials.
	 *
	 * @param ignoreMissingCredentials Whether to ignore missing OAuth credentials.
	 */
	public void setIgnoreMissingCredentials(boolean ignoreMissingCredentials) {
		this.ignoreMissingCredentials = ignoreMissingCredentials;
	}

	/**
	 * The authentication handler.
	 *
	 * @return The authentication handler.
	 */
	public OAuthAuthenticationHandler getAuthHandler() {
		return authHandler;
	}

	/**
	 * The authentication handler.
	 *
	 * @param authHandler The authentication handler.
	 */
	public void setAuthHandler(OAuthAuthenticationHandler authHandler) {
		this.authHandler = authHandler;
	}

	public FrameworkEndpointHandlerMapping getFrameworkEndpointHandlerMapping() {
		return frameworkEndpointHandlerMapping;
	}

	public void setFrameworkEndpointHandlerMapping(FrameworkEndpointHandlerMapping frameworkEndpointHandlerMapping) {
		this.frameworkEndpointHandlerMapping = frameworkEndpointHandlerMapping;
	}
}