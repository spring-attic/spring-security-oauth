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

import java.security.Principal;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.common.exceptions.UnapprovedClientAuthenticationException;
import org.springframework.security.oauth2.common.exceptions.UnsupportedResponseTypeException;
import org.springframework.security.oauth2.common.exceptions.UserDeniedAuthorizationException;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.DefaultRedirectResolver;
import org.springframework.security.oauth2.provider.code.DefaultUserApprovalHandler;
import org.springframework.security.oauth2.provider.code.RedirectResolver;
import org.springframework.security.oauth2.provider.code.UnconfirmedAuthorizationCodeAuthenticationTokenHolder;
import org.springframework.security.oauth2.provider.code.UnconfirmedAuthorizationCodeClientToken;
import org.springframework.security.oauth2.provider.code.UserApprovalHandler;
import org.springframework.stereotype.Controller;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.servlet.View;
import org.springframework.web.servlet.view.RedirectView;

/**
 * @author Dave Syer
 * 
 */
@Controller
@SessionAttributes(types = UnconfirmedAuthorizationCodeClientToken.class)
public class AuthorizationEndpoint extends AbstractEndpoint {

	private ClientDetailsService clientDetailsService;

	private AuthorizationCodeServices authorizationCodeServices;

	private RedirectResolver redirectResolver = new DefaultRedirectResolver();

	private UserApprovalHandler userApprovalHandler = new DefaultUserApprovalHandler();

	private String userApprovalPage = "forward:/oauth/confirm_access";

	public void afterPropertiesSet() throws Exception {
		super.afterPropertiesSet();
		Assert.state(clientDetailsService != null, "ClientDetailsService must be provided");
		Assert.state(authorizationCodeServices != null, "AuthorizationCodeServices must be provided");
	}

	@ModelAttribute
	public UnconfirmedAuthorizationCodeClientToken getClientToken(@RequestHeader HttpHeaders headers,
			@RequestParam(value = "client_id", required = false) String clientId,
			@RequestParam(value = "client_secret", required = false) String clientSecret,
			@RequestParam(value = "redirect_uri", required = false) String redirectUri,
			@RequestParam(value = "state", required = false) String state,
			@RequestParam(value = "scope", required = false) String scopes) {
		Set<String> scope = OAuth2Utils.parseScope(scopes);
		Map<String, String> parameters = new HashMap<String, String>();
		parameters.put("client_id", clientId);
		parameters.put("client_secret", clientSecret);
		String[] values = findClientSecret(headers, parameters);
		UnconfirmedAuthorizationCodeClientToken unconfirmedAuthorizationCodeToken = new UnconfirmedAuthorizationCodeClientToken(
				values[0], values[1], scope, state, redirectUri);
		return unconfirmedAuthorizationCodeToken;
	}

	// if the "response_type" is "code", we can process this request.
	@RequestMapping(value = "/oauth/authorize", params = "response_type=code", method = RequestMethod.GET)
	public String startAuthorization(Map<String, Object> model, @RequestParam Map<String, String> parameters,
			UnconfirmedAuthorizationCodeClientToken authToken, SessionStatus sessionStatus, Principal principal) {

		if (authToken.getClientId() == null) {
			sessionStatus.setComplete();
			throw new InvalidClientException("A client_id must be supplied.");
		}

		if (!(principal instanceof Authentication)) {
			throw new InsufficientAuthenticationException(
					"User must be authenticated with Spring Security before authorizing an access token.");
		}

		logger.debug("Loading user approval page: " + userApprovalPage);
		// In case of a redirect we might want the request parameters to be included
		model.putAll(parameters);
		return userApprovalPage;

	}

	// if the "response_type" is "token", we can process this request.
	@RequestMapping(value = "/oauth/authorize", params = "response_type=token")
	public View implicitAuthorization(UnconfirmedAuthorizationCodeClientToken authToken, SessionStatus sessionStatus, Principal principal) {

		if (authToken.getClientId() == null) {
			sessionStatus.setComplete();
			throw new InvalidClientException("A client_id must be supplied.");
		}
		else {
			authToken.setDenied(false);
		}

		if (!(principal instanceof Authentication)) {
			throw new InsufficientAuthenticationException(
					"User must be authenticated with Spring Security before authorizing an access token.");
		}

		try {
			String requestedRedirect = redirectResolver.resolveRedirect(authToken.getRequestedRedirect(),
					clientDetailsService.loadClientByClientId(authToken.getClientId()));
			OAuth2AccessToken accessToken = getTokenGranter().grant("implicit",
					Collections.<String, String> emptyMap(), authToken.getClientId(), authToken.getClientSecret(),
					authToken.getScope());
			return new RedirectView(appendAccessToken(requestedRedirect, accessToken), false);
		}
		catch (OAuth2Exception e) {
			return new RedirectView(getUnsuccessfulRedirect(authToken, e), false);
		}
		finally {
			sessionStatus.setComplete();
		}

	}

	@RequestMapping(value = "/oauth/authorize", method = RequestMethod.GET)
	public String rejectAuthorization(@RequestParam("response_type") String responseType) {
		throw new UnsupportedResponseTypeException("Unsupported response type: " + responseType);
	}

	@RequestMapping(value = "/oauth/authorize", method = RequestMethod.POST)
	public View approveOrDeny(@RequestParam("user_oauth_approval") boolean approved,
			UnconfirmedAuthorizationCodeClientToken authToken, SessionStatus sessionStatus, Principal principal) {

		if (authToken.getClientId() == null) {
			throw new InvalidClientException("A client_id must be supplied.");
		}
		else {
			authToken.setDenied(!approved);
		}

		if (!(principal instanceof Authentication)) {
			throw new InsufficientAuthenticationException(
					"User must be authenticated with Spring Security before authorizing an access token.");
		}

		try {
			Authentication authUser = (Authentication) principal;
			return new RedirectView(getSuccessfulRedirect(authToken, generateCode(authToken, authUser)), false);
		}
		catch (OAuth2Exception e) {
			return new RedirectView(getUnsuccessfulRedirect(authToken, e), false);
		}
		finally {
			sessionStatus.setComplete();
		}

	}

	private String appendAccessToken(String requestedRedirect, OAuth2AccessToken accessToken) {
		if (accessToken == null) {
			throw new InvalidGrantException("An implicit grant could not be made");
		}
		StringBuilder url = new StringBuilder(requestedRedirect);
		if (requestedRedirect.contains("#")) {
			url.append("&");
		}
		else {
			url.append("#");
		}
		url.append("access_token=" + accessToken.getValue());
		url.append("&token_type=" + accessToken.getTokenType());
		Date expiration = accessToken.getExpiration();
		if (expiration != null) {
			long expires_in = (expiration.getTime() - System.currentTimeMillis()) / 1000;
			url.append("&expires_in=" + expires_in);
		}
		return url.toString();
	}

	private String generateCode(UnconfirmedAuthorizationCodeClientToken authToken, Authentication authentication)
			throws AuthenticationException {

		try {
			if (authToken.isDenied()) {
				throw new UserDeniedAuthorizationException("User denied authorization of the authorization code.");
			}
			else if (!userApprovalHandler.isApproved(authToken)) {
				throw new UnapprovedClientAuthenticationException(
						"The authorization hasn't been approved by the current user.");
			}

			String clientId = authToken.getClientId();
			ClientDetails client = clientDetailsService.loadClientByClientId(clientId);
			String requestedRedirect = authToken.getRequestedRedirect();
			String redirectUri = redirectResolver.resolveRedirect(requestedRedirect, client);
			if (redirectUri == null) {
				throw new OAuth2Exception("A redirect_uri must be supplied.");
			}

			UnconfirmedAuthorizationCodeAuthenticationTokenHolder combinedAuth = new UnconfirmedAuthorizationCodeAuthenticationTokenHolder(
					authToken, authentication);
			String code = authorizationCodeServices.createAuthorizationCode(combinedAuth);

			return code;

		}
		catch (OAuth2Exception e) {

			if (authToken.getState() != null) {
				e.addAdditionalInformation("state", authToken.getState());
			}

			throw e;

		}
	}

	protected String getSuccessfulRedirect(UnconfirmedAuthorizationCodeClientToken clientAuth, String authorizationCode) {

		if (authorizationCode == null) {
			throw new IllegalStateException("No authorization code found in the current request scope.");
		}

		String requestedRedirect = redirectResolver.resolveRedirect(clientAuth.getRequestedRedirect(),
				clientDetailsService.loadClientByClientId(clientAuth.getClientId()));
		String state = clientAuth.getState();

		StringBuilder url = new StringBuilder(requestedRedirect);
		if (requestedRedirect.indexOf('?') < 0) {
			url.append('?');
		}
		else {
			url.append('&');
		}
		url.append("code=").append(authorizationCode);

		if (state != null) {
			url.append("&state=").append(state);
		}

		return url.toString();
	}

	protected String getUnsuccessfulRedirect(UnconfirmedAuthorizationCodeClientToken token, OAuth2Exception failure) {

		// TODO: allow custom failure handling?
		if (token == null || token.getRequestedRedirect() == null) {
			// we have no redirect for the user. very sad.
			throw new UnapprovedClientAuthenticationException("Authorization failure, and no redirect URI.", failure);
		}

		String redirectUri = token.getRequestedRedirect();
		StringBuilder url = new StringBuilder(redirectUri);
		if (redirectUri.indexOf('?') < 0) {
			url.append('?');
		}
		else {
			url.append('&');
		}
		url.append("error=").append(failure.getOAuth2ErrorCode());
		url.append("&error_description=").append(failure.getMessage());

		if (failure.getAdditionalInformation() != null) {
			for (Map.Entry<String, String> additionalInfo : failure.getAdditionalInformation().entrySet()) {
				url.append('&').append(additionalInfo.getKey()).append('=').append(additionalInfo.getValue());
			}
		}

		return url.toString();

	}

	public void setUserApprovalPage(String userApprovalPage) {
		this.userApprovalPage = userApprovalPage;
	}

	public void setClientDetailsService(ClientDetailsService clientDetailsService) {
		this.clientDetailsService = clientDetailsService;
	}

	public void setAuthorizationCodeServices(AuthorizationCodeServices authorizationCodeServices) {
		this.authorizationCodeServices = authorizationCodeServices;
	}

	public void setRedirectResolver(RedirectResolver redirectResolver) {
		this.redirectResolver = redirectResolver;
	}

	public void setUserApprovalHandler(UserApprovalHandler userApprovalHandler) {
		this.userApprovalHandler = userApprovalHandler;
	}

}
