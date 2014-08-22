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
package org.springframework.security.oauth.provider.endpoint;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth.common.OAuthConstants;
import org.springframework.security.oauth.provider.InvalidOAuthParametersException;
import org.springframework.security.oauth.provider.token.InvalidOAuthTokenException;
import org.springframework.security.oauth.provider.token.OAuthProviderToken;
import org.springframework.security.oauth.provider.verifier.OAuthVerifierServices;
import org.springframework.security.web.authentication.*;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Handles requests to authenticate an OAuth request token.
 * <p>
 * This end point looks for one request parameter for the token id that is being authorized.
 * The default name of the parameter is "requestToken", but this can be configured.
 * </p>
 *
 * @author Ryan Heaton
 * @author Andrew McCall
 * @author <a rel="author" href="http://autayeu.com/">Aliaksandr Autayeu</a>
 */
@FrameworkEndpoint ( oauthAuthenticationRequired = false )
public class AuthorizationEndpoint extends AbstractEndpoint implements InitializingBean {

	// mixed terminology of authentication and authorization used here
	// because the token is being authenticated,
	// while the (access to the) resource (which the token represents) is being authorized

	protected static final String CALLBACK_ATTRIBUTE = AuthorizationEndpoint.class.getName() + "#CALLBACK";
	protected static final String VERIFIER_ATTRIBUTE = AuthorizationEndpoint.class.getName() + "#VERIFIER";

	private String tokenIdParameterName = "requestToken";
	private RememberMeServices rememberMeServices = new NullRememberMeServices();
	protected ApplicationEventPublisher applicationEventPublisher;
	private OAuthVerifierServices verifierServices;

	private AuthenticationSuccessHandler authenticationSuccessHandler = new SavedRequestAwareAuthenticationSuccessHandler();
	private AuthenticationFailureHandler authenticationFailureHandler = new SimpleUrlAuthenticationFailureHandler();

	@Override
	public void afterPropertiesSet() {
		Assert.notNull(getTokenServices(), "A token services must be provided.");
		Assert.notNull(getVerifierServices(), "Verifier services are required.");
	}

	@RequestMapping ( value = OAuthConstants.DEFAULT_AUTHENTICATE_TOKEN_URL, method = {RequestMethod.GET, RequestMethod.POST} )
	@ResponseBody
	public void authorize(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
		String requestToken = request.getParameter(getTokenIdParameterName());
		if (requestToken == null) {
			throw new InvalidOAuthParametersException("An OAuth request token is required.");
		}

		// check authentication first - it might save a db call in token services :)
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication == null || !authentication.isAuthenticated()) {
			throw new InsufficientAuthenticationException("User must be authenticated before authorizing a request token.");
		}

		OAuthProviderToken token = getTokenServices().getToken(requestToken);
		if (token == null) {
			throw new InvalidOAuthTokenException("Invalid token: " + requestToken + ".");
		}

		String callbackURL = token.getCallbackUrl();
		if (isRequire10a() && callbackURL == null) {
			throw new InvalidOAuthTokenException("No callback value has been provided for request token " + requestToken + ".");
		}

		if (callbackURL != null) {
			request.setAttribute(CALLBACK_ATTRIBUTE, callbackURL);
		}

		String verifier = getVerifierServices().createVerifier();
		request.setAttribute(VERIFIER_ATTRIBUTE, verifier);
		getTokenServices().authorizeRequestToken(requestToken, verifier, authentication);

		successfulAuthentication(request, response, authentication);
	}

	@ExceptionHandler ( AuthenticationException.class )
	public void handleAuthenticationException(AuthenticationException e, HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
		unsuccessfulAuthentication(request, response, e);
	}

	/**
	 * Default behaviour for successful authentication.
	 * <ol>
	 * <li>Sets the successful <tt>Authentication</tt> object on the {@link SecurityContextHolder}</li>
	 * <li>Informs the configured <tt>RememberMeServices</tt> of the successful login</li>
	 * <li>Fires an {@link org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent} via the configured
	 * <tt>ApplicationEventPublisher</tt></li>
	 * <li>Delegates additional behaviour to the {@link org.springframework.security.web.authentication.AuthenticationSuccessHandler}.</li>
	 * </ol>
	 *
	 * @param authResult the authentication object.
	 */
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
											Authentication authResult) throws IOException, ServletException {
		if (logger.isDebugEnabled()) {
			logger.debug("Authentication success. Updating SecurityContextHolder to contain: " + authResult);
		}

		SecurityContextHolder.getContext().setAuthentication(authResult);

		rememberMeServices.loginSuccess(request, response, authResult);

		// Fire event
		if (this.applicationEventPublisher != null) {
			applicationEventPublisher.publishEvent(new InteractiveAuthenticationSuccessEvent(authResult, this.getClass()));
		}

		authenticationSuccessHandler.onAuthenticationSuccess(request, response, authResult);
	}

	/**
	 * Default behaviour for unsuccessful authentication.
	 * <ol>
	 * <li>Clears the {@link SecurityContextHolder}</li>
	 * <li>Informs the configured <tt>RememberMeServices</tt> of the failed login</li>
	 * <li>Delegates additional behaviour to the {@link org.springframework.security.web.authentication.AuthenticationFailureHandler}.</li>
	 * </ol>
	 */
	protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
											  AuthenticationException failed) throws IOException, ServletException {
		SecurityContextHolder.clearContext();

		if (logger.isDebugEnabled()) {
			logger.debug("Authentication request failed: " + failed.toString());
			logger.debug("Updated SecurityContextHolder to contain null Authentication");
			logger.debug("Delegating to authentication failure handler " + authenticationFailureHandler);
		}

		rememberMeServices.loginFail(request, response);

		authenticationFailureHandler.onAuthenticationFailure(request, response, failed);
	}

	/**
	 * The name of the request parameter that supplies the token id.
	 *
	 * @return The name of the request parameter that supplies the token id.
	 */
	public String getTokenIdParameterName() {
		return tokenIdParameterName;
	}

	/**
	 * The name of the request parameter that supplies the token id.
	 *
	 * @param tokenIdParameterName The name of the request parameter that supplies the token id.
	 */
	public void setTokenIdParameterName(String tokenIdParameterName) {
		this.tokenIdParameterName = tokenIdParameterName;
	}

	/**
	 * The verifier services to use.
	 *
	 * @return The verifier services to use.
	 */
	public OAuthVerifierServices getVerifierServices() {
		return verifierServices;
	}

	/**
	 * The verifier services to use.
	 *
	 * @param verifierServices The verifier services to use.
	 */
	@Autowired
	public void setVerifierServices(OAuthVerifierServices verifierServices) {
		this.verifierServices = verifierServices;
	}

	public RememberMeServices getRememberMeServices() {
		return rememberMeServices;
	}

	public void setRememberMeServices(RememberMeServices rememberMeServices) {
		Assert.notNull("rememberMeServices cannot be null");
		this.rememberMeServices = rememberMeServices;
	}

	public void setApplicationEventPublisher(ApplicationEventPublisher eventPublisher) {
		this.applicationEventPublisher = eventPublisher;
	}

	public ApplicationEventPublisher getApplicationEventPublisher() {
		return applicationEventPublisher;
	}

	/**
	 * Sets the strategy used to handle a successful authentication.
	 * By default a {@link SavedRequestAwareAuthenticationSuccessHandler} is used.
	 */
	public void setAuthenticationSuccessHandler(AuthenticationSuccessHandler successHandler) {
		Assert.notNull(successHandler, "authenticationSuccessHandler cannot be null");
		this.authenticationSuccessHandler = successHandler;
	}

	public void setAuthenticationFailureHandler(AuthenticationFailureHandler failureHandler) {
		Assert.notNull(failureHandler, "authenticationFailureHandler cannot be null");
		this.authenticationFailureHandler = failureHandler;
	}

	protected AuthenticationSuccessHandler getAuthenticationSuccessHandler() {
		return authenticationSuccessHandler;
	}

	protected AuthenticationFailureHandler getAuthenticationFailureHandler() {
		return authenticationFailureHandler;
	}
}