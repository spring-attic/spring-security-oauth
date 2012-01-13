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
import java.util.Date;
import java.util.Map;
import java.util.Set;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.common.exceptions.UnapprovedClientAuthenticationException;
import org.springframework.security.oauth2.common.exceptions.UnsupportedGrantTypeException;
import org.springframework.security.oauth2.common.exceptions.UnsupportedResponseTypeException;
import org.springframework.security.oauth2.common.exceptions.UserDeniedAuthorizationException;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.AuthorizationRequestHolder;
import org.springframework.security.oauth2.provider.code.DefaultUserApprovalHandler;
import org.springframework.security.oauth2.provider.code.InMemoryAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.UserApprovalHandler;
import org.springframework.stereotype.Controller;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.View;
import org.springframework.web.servlet.view.RedirectView;

/**
 * @author Dave Syer
 * 
 */
@Controller
@SessionAttributes(types = AuthorizationRequest.class)
@RequestMapping(value = "/oauth/authorize")
public class AuthorizationEndpoint extends AbstractEndpoint implements InitializingBean {

	public static final String USER_OAUTH_APPROVAL = "user_oauth_approval";

	public static final String RESPONSE_TYPE = "response_type";

	private ClientDetailsService clientDetailsService;

	private AuthorizationCodeServices authorizationCodeServices = new InMemoryAuthorizationCodeServices();

	private RedirectResolver redirectResolver = new DefaultRedirectResolver();

	private UserApprovalHandler userApprovalHandler = new DefaultUserApprovalHandler();

	private String userApprovalPage = "forward:/oauth/confirm_access";

	public void afterPropertiesSet() throws Exception {
		super.afterPropertiesSet();
		Assert.state(clientDetailsService != null, "ClientDetailsService must be provided");
	}

	@ModelAttribute
	public AuthorizationRequest getClientToken(@RequestParam Map<String, String> parameters) {
		AuthorizationRequest authorizationRequest = new AuthorizationRequest(parameters);
		return authorizationRequest;
	}

	@RequestMapping(params = "response_type")
	public ModelAndView authorize(Map<String, Object> model, @RequestParam("response_type") String responseType,
			@RequestParam(value = USER_OAUTH_APPROVAL, required = false) Boolean approved,
			@ModelAttribute AuthorizationRequest authorizationRequest, SessionStatus sessionStatus, Principal principal) {

		if (authorizationRequest.getClientId() == null) {
			sessionStatus.setComplete();
			throw new InvalidClientException("A client_id must be supplied.");
		}

		if (!(principal instanceof Authentication) || !((Authentication) principal).isAuthenticated()) {
			sessionStatus.setComplete();
			throw new InsufficientAuthenticationException(
					"User must be authenticated with Spring Security before forwarding to user approval page.");
		}

		Set<String> responseTypes = OAuth2Utils.parseParameterList(responseType);

		if (responseTypes.contains("code")) {
			authorizationRequest = resolveRedirectUri(authorizationRequest);
			if (approved != null) {
				return new ModelAndView(getAuthorizationCodeResponse(authorizationRequest.denied(!approved),
						(Authentication) principal));
			}
			return getUserApprovalPageResponse(model, authorizationRequest);
		}

		try {
			authorizationRequest = resolveRedirectUri(authorizationRequest);
			if (responseTypes.contains("token")) {
				return getImplicitGrantResponse(authorizationRequest);
			}
			throw new UnsupportedResponseTypeException("Unsupported response type: " + responseType);
		}
		finally {
			sessionStatus.setComplete();
		}

	}

	@RequestMapping(method = RequestMethod.POST)
	public View approveOrDeny(@RequestParam(USER_OAUTH_APPROVAL) boolean approved,
			@ModelAttribute AuthorizationRequest authorizationRequest, SessionStatus sessionStatus, Principal principal) {

		if (authorizationRequest.getClientId() == null) {
			sessionStatus.setComplete();
			throw new InvalidClientException("A client_id must be supplied.");
		}

		if (!(principal instanceof Authentication)) {
			sessionStatus.setComplete();
			throw new InsufficientAuthenticationException(
					"User must be authenticated with Spring Security before authorizing an access token.");
		}

		try {
			authorizationRequest = resolveRedirectUri(authorizationRequest);
			return getAuthorizationCodeResponse(authorizationRequest.denied(!approved), (Authentication) principal);
		}
		finally {
			sessionStatus.setComplete();
		}

	}

	/**
	 * Enhance the AuthorizationRequest, resolving the redirect uri if possible, and throwing an exception otherwise.
	 * 
	 * @param authorizationRequest the current request
	 * @return an authorization request with the redirect uri resolved
	 * @throws OAuth2Exception if the redirect uri or client is invalid
	 */
	private AuthorizationRequest resolveRedirectUri(AuthorizationRequest authorizationRequest) throws OAuth2Exception {
		String requestedRedirect = redirectResolver.resolveRedirect(authorizationRequest.getRedirectUri(),
				clientDetailsService.loadClientByClientId(authorizationRequest.getClientId()));
		return authorizationRequest.resolveRedirectUri(requestedRedirect);
	}

	// We need explicit approval from the user.
	private ModelAndView getUserApprovalPageResponse(Map<String, Object> model,
			AuthorizationRequest authorizationRequest) {
		logger.debug("Loading user approval page: " + userApprovalPage);
		// In case of a redirect we might want the request parameters to be included
		model.putAll(authorizationRequest.getParameters());
		return new ModelAndView(userApprovalPage, model);
	}

	// We can grant a token and return it with implicit approval.
	private ModelAndView getImplicitGrantResponse(AuthorizationRequest authorizationRequest) {
		try {
			OAuth2AccessToken accessToken = getTokenGranter().grant("implicit", authorizationRequest.getParameters(),
					authorizationRequest.getClientId(), authorizationRequest.getScope());
			if (accessToken == null) {
				throw new UnsupportedGrantTypeException("Unsupported grant type: implicit");
			}
			return new ModelAndView(new RedirectView(appendAccessToken(authorizationRequest, accessToken), false));
		}
		catch (OAuth2Exception e) {
			return new ModelAndView(new RedirectView(getUnsuccessfulRedirect(authorizationRequest, e), false));
		}
	}

	private View getAuthorizationCodeResponse(AuthorizationRequest authorizationRequest, Authentication authUser) {
		try {
			return new RedirectView(getSuccessfulRedirect(authorizationRequest,
					generateCode(authorizationRequest, authUser)), false);
		}
		catch (OAuth2Exception e) {
			return new RedirectView(getUnsuccessfulRedirect(authorizationRequest, e), false);
		}
	}

	private String appendAccessToken(AuthorizationRequest authorizationRequest, OAuth2AccessToken accessToken) {
		String requestedRedirect = authorizationRequest.getRedirectUri();
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

	private String generateCode(AuthorizationRequest authorizationRequest, Authentication authentication)
			throws AuthenticationException {

		try {
			if (authorizationRequest.isDenied()) {
				throw new UserDeniedAuthorizationException("User denied authorization of the authorization code.");
			}
			else if (!userApprovalHandler.isApproved(authorizationRequest)) {
				throw new UnapprovedClientAuthenticationException(
						"The authorization hasn't been approved by the current user.");
			}

			AuthorizationRequestHolder combinedAuth = new AuthorizationRequestHolder(authorizationRequest,
					authentication);
			String code = authorizationCodeServices.createAuthorizationCode(combinedAuth);

			return code;

		}
		catch (OAuth2Exception e) {

			if (authorizationRequest.getState() != null) {
				e.addAdditionalInformation("state", authorizationRequest.getState());
			}

			throw e;

		}
	}

	private String getSuccessfulRedirect(AuthorizationRequest authorizationRequest, String authorizationCode) {

		if (authorizationCode == null) {
			throw new IllegalStateException("No authorization code found in the current request scope.");
		}

		String requestedRedirect = authorizationRequest.getRedirectUri();
		String state = authorizationRequest.getState();

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

	private String getUnsuccessfulRedirect(AuthorizationRequest authorizationRequest, OAuth2Exception failure) {

		// TODO: allow custom failure handling?
		if (authorizationRequest == null || authorizationRequest.getRedirectUri() == null) {
			// we have no redirect for the user. very sad.
			throw new UnapprovedClientAuthenticationException("Authorization failure, and no redirect URI.", failure);
		}

		String redirectUri = authorizationRequest.getRedirectUri();
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
