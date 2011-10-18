/*
 * Copyright 2002-2011 the original author or authors.
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

package org.springframework.security.oauth2.provider.endpoint;

import java.io.IOException;
import java.util.Map;
import java.util.Set;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.common.exceptions.UnapprovedClientAuthenticationException;
import org.springframework.security.oauth2.common.exceptions.UnsupportedResponseTypeException;
import org.springframework.security.oauth2.common.exceptions.UserDeniedAuthorizationException;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.ClientTokenCache;
import org.springframework.security.oauth2.provider.code.DefaultClientTokenCache;
import org.springframework.security.oauth2.provider.code.DefaultRedirectResolver;
import org.springframework.security.oauth2.provider.code.DefaultUserApprovalHandler;
import org.springframework.security.oauth2.provider.code.RedirectResolver;
import org.springframework.security.oauth2.provider.code.UnconfirmedAuthorizationCodeClientToken;
import org.springframework.security.oauth2.provider.code.UnconfirmedAuthorizationCodeAuthenticationTokenHolder;
import org.springframework.security.oauth2.provider.code.UserApprovalHandler;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.stereotype.Controller;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * @author Dave Syer
 * 
 */
@Controller
public class AuthorizationEndpoint implements InitializingBean {

	private static final Log logger = LogFactory.getLog(AuthorizationEndpoint.class);

	private static final String AUTHORIZATION_CODE_ATTRIBUTE = AuthorizationEndpoint.class.getName() + "#CODE";
	private static final String AUTHORIZATION_CODE_TOKEN_ATTRIBUTE = AuthorizationEndpoint.class.getName() + "#TOKEN";

	private ClientTokenCache clientTokenCache = new DefaultClientTokenCache();
	private ClientDetailsService clientDetailsService;
	private AuthorizationCodeServices authorizationCodeServices;
	private RedirectResolver redirectResolver = new DefaultRedirectResolver();
	private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
	private UserApprovalHandler userApprovalHandler = new DefaultUserApprovalHandler();

	private String userApprovalPage = "forward:/oauth/confirm_access";

	public void afterPropertiesSet() throws Exception {
		Assert.state(clientDetailsService != null, "ClientDetailsService must be provided");
		Assert.state(authorizationCodeServices != null, "AuthorizationCodeServices must be provided");
	}

	@RequestMapping(value = "/oauth/authorize", method = RequestMethod.GET)
	public String startAuthorization(@RequestParam("response_type") String responseType, HttpServletRequest request,
			HttpServletResponse response) throws IOException, ServletException {
		if ("code".equals(responseType)) {
			// if the "response_type" is "code", we can process this request.
			String clientId = request.getParameter("client_id");
			String redirectUri = request.getParameter("redirect_uri");
			Set<String> scope = OAuth2Utils.parseScope(request.getParameter("scope"));
			String state = request.getParameter("state");
			UnconfirmedAuthorizationCodeClientToken unconfirmedAuthorizationCodeToken = new UnconfirmedAuthorizationCodeClientToken(
					clientId, scope, state, redirectUri);
			if (clientId == null) {
				request.setAttribute(AUTHORIZATION_CODE_TOKEN_ATTRIBUTE, unconfirmedAuthorizationCodeToken);
				throw new InvalidClientException("A client_id parameter must be supplied.");
			} else {
				clientTokenCache.saveToken(unconfirmedAuthorizationCodeToken, request, response);
				logger.debug("Forwarding to " + userApprovalPage);
				// request.getRequestDispatcher(userApprovalPage).forward(request, response);
				return userApprovalPage;
			}
		} else {
			throw new UnsupportedResponseTypeException("Unsupported response type: " + responseType);
		}
	}

	@RequestMapping(value = "/oauth/authorize", method = RequestMethod.POST)
	public void approveOrDeny(@RequestParam("user_oauth_approval") boolean approved, HttpServletRequest request,
			HttpServletResponse response) throws IOException, ServletException {

		UnconfirmedAuthorizationCodeClientToken authToken = clientTokenCache.getToken((HttpServletRequest) request,
				(HttpServletResponse) response);
		if (authToken == null) {
			throw new AuthenticationServiceException(
					"Request parameter 'user_oauth_approval' may only be applied in the middle of an oauth web server approval profile.");
		} else {
			authToken.setDenied(!approved);
		}

		try {
			successfulAuthentication(request, response, attemptAuthentication(request, response));
		} catch (OAuth2Exception e) {
			// TODO: handle UnapprovedClientAuthenticationException
			unsuccessfulAuthentication(request, response, e);
		} finally {
			clientTokenCache.removeToken(authToken, request, response);
		}

	}

	private Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication == null || !authentication.isAuthenticated()) {
			throw new InsufficientAuthenticationException(
					"User must be authenticated before authorizing an access token.");
		}

		UnconfirmedAuthorizationCodeClientToken saved = clientTokenCache.getToken(request, response);
		if (saved == null) {
			throw new InsufficientAuthenticationException("No client authentication request has been issued.");
		}

		request.setAttribute(AUTHORIZATION_CODE_TOKEN_ATTRIBUTE, saved);
		try {
			if (saved.isDenied()) {
				throw new UserDeniedAuthorizationException("User denied authorization of the authorization code.");
			} else if (!userApprovalHandler.isApproved(saved)) {
				throw new UnapprovedClientAuthenticationException(
						"The authorization hasn't been approved by the current user.");
			}

			String clientId = saved.getClientId();
			if (clientId == null) {
				throw new InvalidClientException("Invalid authorization request (no client id).");
			}

			ClientDetails client = clientDetailsService.loadClientByClientId(clientId);
			String requestedRedirect = saved.getRequestedRedirect();
			String redirectUri = redirectResolver.resolveRedirect(requestedRedirect, client);
			if (redirectUri == null) {
				throw new OAuth2Exception("A redirect_uri must be supplied.");
			}

			UnconfirmedAuthorizationCodeAuthenticationTokenHolder combinedAuth = new UnconfirmedAuthorizationCodeAuthenticationTokenHolder(
					saved, authentication);
			String code = authorizationCodeServices.createAuthorizationCode(combinedAuth);
			request.setAttribute(AUTHORIZATION_CODE_ATTRIBUTE, code);
			return new OAuth2Authentication(saved, authentication);
		} catch (OAuth2Exception e) {
			if (saved.getState() != null) {
				e.addAdditionalInformation("state", saved.getState());
			}

			throw e;
		}
	}

	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
			Authentication authResult) throws IOException, ServletException {
		OAuth2Authentication authentication = (OAuth2Authentication) authResult;
		String authorizationCode = (String) request.getAttribute(AUTHORIZATION_CODE_ATTRIBUTE);
		if (authorizationCode == null) {
			throw new IllegalStateException("No authorization code found in the current request scope.");
		}

		UnconfirmedAuthorizationCodeClientToken clientAuth = (UnconfirmedAuthorizationCodeClientToken) authentication
				.getClientAuthentication();
		String requestedRedirect = redirectResolver.resolveRedirect(clientAuth.getRequestedRedirect(),
				clientDetailsService.loadClientByClientId(clientAuth.getClientId()));
		String state = clientAuth.getState();

		StringBuilder url = new StringBuilder(requestedRedirect);
		if (requestedRedirect.indexOf('?') < 0) {
			url.append('?');
		} else {
			url.append('&');
		}
		url.append("code=").append(authorizationCode);

		if (state != null) {
			url.append("&state=").append(state);
		}

		redirectStrategy.sendRedirect(request, response, url.toString());
	}

	protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
			OAuth2Exception failure) throws IOException, ServletException {
		// TODO: allow custom failure handling?
		UnconfirmedAuthorizationCodeClientToken token = (UnconfirmedAuthorizationCodeClientToken) request
				.getAttribute(AUTHORIZATION_CODE_TOKEN_ATTRIBUTE);
		if (token == null || token.getRequestedRedirect() == null) {
			// we have no redirect for the user. very sad.
			throw new UnapprovedClientAuthenticationException("Authorization failure, and no redirect URI.", failure);
		}

		String redirectUri = token.getRequestedRedirect();
		StringBuilder url = new StringBuilder(redirectUri);
		if (redirectUri.indexOf('?') < 0) {
			url.append('?');
		} else {
			url.append('&');
		}
		url.append("error=").append(failure.getOAuth2ErrorCode());
		url.append("&error_description=").append(failure.getMessage());

		if (failure.getAdditionalInformation() != null) {
			for (Map.Entry<String, String> additionalInfo : failure.getAdditionalInformation().entrySet()) {
				url.append('&').append(additionalInfo.getKey()).append('=').append(additionalInfo.getValue());
			}
		}

		redirectStrategy.sendRedirect(request, response, url.toString());

	}

	public void setUserApprovalPage(String userApprovalPage) {
		this.userApprovalPage = userApprovalPage;
	}

	public void setAuthenticationCache(ClientTokenCache authenticationCache) {
		this.clientTokenCache = authenticationCache;
	}

	@Autowired
	public void setClientDetailsService(ClientDetailsService clientDetailsService) {
		this.clientDetailsService = clientDetailsService;
	}

	@Autowired
	public void setAuthorizationCodeServices(AuthorizationCodeServices authorizationCodeServices) {
		this.authorizationCodeServices = authorizationCodeServices;
	}

	public void setRedirectResolver(RedirectResolver redirectResolver) {
		this.redirectResolver = redirectResolver;
	}

	public void setRedirectStrategy(RedirectStrategy redirectStrategy) {
		this.redirectStrategy = redirectStrategy;
	}

	public void setUserApprovalHandler(UserApprovalHandler userApprovalHandler) {
		this.userApprovalHandler = userApprovalHandler;
	}
}
