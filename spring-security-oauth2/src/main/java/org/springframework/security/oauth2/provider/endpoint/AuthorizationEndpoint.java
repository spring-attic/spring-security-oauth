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

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.Principal;
import java.util.Collections;
import java.util.Date;
import java.util.Map;
import java.util.Set;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
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
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.DefaultAuthorizationRequest;
import org.springframework.security.oauth2.provider.approval.DefaultUserApprovalHandler;
import org.springframework.security.oauth2.provider.approval.UserApprovalHandler;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.AuthorizationRequestHolder;
import org.springframework.security.oauth2.provider.code.InMemoryAuthorizationCodeServices;
import org.springframework.util.ClassUtils;
import org.springframework.web.HttpSessionRequiredException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.View;
import org.springframework.web.servlet.view.RedirectView;

/**
 * <p>
 * Implementation of the Authorization Endpoint from the OAuth2 specification. Accepts authorization requests, and
 * handles user approval if the grant type is authorization code. The tokens themselves are obtained from the
 * {@link TokenEndpoint Token Endpoint}, except in the implicit grant type (where they come from the Authorization
 * Endpoint via <code>response_type=token</code>.
 * </p>
 * 
 * <p>
 * This endpoint should be secured so that it is only accessible to fully authenticated users (as a minimum requirement)
 * since it represents a request from a valid user to act on his or her behalf.
 * </p>
 * 
 * @author Dave Syer
 * @author Vladimir Kryachko
 * 
 */
@FrameworkEndpoint
@SessionAttributes("authorizationRequest")
@RequestMapping(value = "/oauth/authorize")
public class AuthorizationEndpoint extends AbstractEndpoint implements InitializingBean {

	private AuthorizationCodeServices authorizationCodeServices = new InMemoryAuthorizationCodeServices();

	private RedirectResolver redirectResolver = new DefaultRedirectResolver();

	private UserApprovalHandler userApprovalHandler = new DefaultUserApprovalHandler();

	private String userApprovalPage = "forward:/oauth/confirm_access";

	private String errorPage = "forward:/oauth/error";

	public void afterPropertiesSet() throws Exception {
		super.afterPropertiesSet();
	}

	public void setErrorPage(String errorPage) {
		this.errorPage = errorPage;
	}

	@RequestMapping(params = "response_type")
	public ModelAndView authorize(Map<String, Object> model, @RequestParam("response_type") String responseType,
			@RequestParam Map<String, String> parameters, SessionStatus sessionStatus, Principal principal) {

		Set<String> responseTypes = OAuth2Utils.parseParameterList(responseType);

		if (!responseTypes.contains("token") && !responseTypes.contains("code")) {
			throw new UnsupportedResponseTypeException("Unsupported response types: " + responseTypes);
		}

		try {

			// Manually initialize auth request instead of using @ModelAttribute
			// to make sure it comes from request instead of the session
			DefaultAuthorizationRequest authorizationRequest = new DefaultAuthorizationRequest(
					getAuthorizationRequestFactory().createAuthorizationRequest(parameters));

			if (!(principal instanceof Authentication) || !((Authentication) principal).isAuthenticated()) {
				throw new InsufficientAuthenticationException(
						"User must be authenticated with Spring Security before authorization can be completed.");
			}

			resolveRedirectUriAndCheckApproval(authorizationRequest, (Authentication) principal);

			// We intentionally only validate the parameters requested by the client (ignoring any data that may have
			// been added to the request by the factory).
			getParametersValidator().validateParameters(parameters,
					getClientDetailsService().loadClientByClientId(authorizationRequest.getClientId()));

			// Validation is all done, so we can check fopr auto approval...
			if (authorizationRequest.isApproved()) {
				if (responseTypes.contains("token")) {
					return getImplicitGrantResponse(authorizationRequest);
				}
				if (responseTypes.contains("code")) {
					return new ModelAndView(getAuthorizationCodeResponse(authorizationRequest,
							(Authentication) principal));
				}
			}

			// Place auth request into the model so that it is stored in the session
			// for approveOrDeny to use. That way we make sure that auth request comes from the session,
			// so any auth request parameters passed to approveOrDeny will be ignored and retrieved from the session.
			model.put("authorizationRequest", authorizationRequest);

			return getUserApprovalPageResponse(model, authorizationRequest);

		}
		catch (RuntimeException e) {
			sessionStatus.setComplete();
			throw e;
		}

	}

	@RequestMapping(method = RequestMethod.POST, params = AuthorizationRequest.USER_OAUTH_APPROVAL)
	public View approveOrDeny(@RequestParam Map<String, String> approvalParameters,
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
			Set<String> responseTypes = authorizationRequest.getResponseTypes();

			DefaultAuthorizationRequest outgoingRequest = new DefaultAuthorizationRequest(authorizationRequest);
			outgoingRequest.setApprovalParameters(approvalParameters);
			resolveRedirectUriAndCheckApproval(outgoingRequest, (Authentication) principal);

			if (!outgoingRequest.isApproved()) {
				return new RedirectView(getUnsuccessfulRedirect(outgoingRequest, new UserDeniedAuthorizationException(
						"User denied access"), responseTypes.contains("token")), false);
			}

			if (responseTypes.contains("token")) {
				return getImplicitGrantResponse(outgoingRequest).getView();
			}

			return getAuthorizationCodeResponse(outgoingRequest, (Authentication) principal);
		}
		finally {
			sessionStatus.setComplete();
		}

	}

	/**
	 * Enhance the AuthorizationRequest, resolving the redirect uri if possible, throwing an exception otherwise, and
	 * then checking to see if the request has been authorized, setting the flag appropriately.
	 * 
	 * @param authorizationRequest the current request
	 * @param authentication the current authentication token
	 * 
	 * @return an authorization request with the redirect uri resolved and approved flag set
	 * @throws OAuth2Exception if the redirect uri or client is invalid
	 */
	private void resolveRedirectUriAndCheckApproval(DefaultAuthorizationRequest authorizationRequest,
			Authentication authentication) throws OAuth2Exception {

		String requestedRedirect = redirectResolver.resolveRedirect(authorizationRequest.getRedirectUri(),
				getClientDetailsService().loadClientByClientId(authorizationRequest.getClientId()));
		authorizationRequest.setRedirectUri(requestedRedirect);

		boolean approved = authorizationRequest.isApproved();
		if (!approved) {
			approved = userApprovalHandler.isApproved(authorizationRequest, authentication);
			authorizationRequest.setApproved(approved);
		}

	}

	// We need explicit approval from the user.
	private ModelAndView getUserApprovalPageResponse(Map<String, Object> model,
			AuthorizationRequest authorizationRequest) {
		logger.debug("Loading user approval page: " + userApprovalPage);
		// In case of a redirect we might want the request parameters to be included
		model.putAll(authorizationRequest.getAuthorizationParameters());
		return new ModelAndView(userApprovalPage, model);
	}

	// We can grant a token and return it with implicit approval.
	private ModelAndView getImplicitGrantResponse(AuthorizationRequest authorizationRequest) {
		try {
			OAuth2AccessToken accessToken = getTokenGranter().grant("implicit", authorizationRequest);
			if (accessToken == null) {
				throw new UnsupportedResponseTypeException("Unsupported response type: token");
			}
			return new ModelAndView(new RedirectView(appendAccessToken(authorizationRequest, accessToken), false));
		}
		catch (OAuth2Exception e) {
			return new ModelAndView(new RedirectView(getUnsuccessfulRedirect(authorizationRequest, e, true), false));
		}
	}

	private View getAuthorizationCodeResponse(AuthorizationRequest authorizationRequest, Authentication authUser) {
		try {
			return new RedirectView(getSuccessfulRedirect(authorizationRequest,
					generateCode(authorizationRequest, authUser)), false);
		}
		catch (OAuth2Exception e) {
			return new RedirectView(getUnsuccessfulRedirect(authorizationRequest, e, false), false);
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
		String state = authorizationRequest.getState();
		if (state != null) {
			url.append("&state=" + state);
		}
		Date expiration = accessToken.getExpiration();
		if (expiration != null) {
			long expires_in = (expiration.getTime() - System.currentTimeMillis()) / 1000;
			url.append("&expires_in=" + expires_in);
		}
		Map<String, Object> additionalInformation = accessToken.getAdditionalInformation();
		for (String key : additionalInformation.keySet()) {
			Object value = additionalInformation.get(key);
			if (value != null && ClassUtils.isPrimitiveOrWrapper(value.getClass())) {
				url.append("&" + key + "=" + value);
			}
		}
		// Do not include the refresh token (even if there is one)
		return url.toString();
	}

	private String generateCode(AuthorizationRequest authorizationRequest, Authentication authentication)
			throws AuthenticationException {

		try {

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
		String[] fragments = requestedRedirect.split("#");
		String state = authorizationRequest.getState();

		StringBuilder url = new StringBuilder(fragments[0]);
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

		if (fragments.length > 1) {
			url.append("#" + fragments[1]);
		}

		return url.toString();
	}

	private String getUnsuccessfulRedirect(AuthorizationRequest authorizationRequest, OAuth2Exception failure,
			boolean fragment) {

		if (authorizationRequest == null || authorizationRequest.getRedirectUri() == null) {
			// we have no redirect for the user. very sad.
			throw new UnapprovedClientAuthenticationException("Authorization failure, and no redirect URI.", failure);
		}

		String redirectUri = authorizationRequest.getRedirectUri();

		// extract existing fragments if any
		String[] fragments = redirectUri.split("#");

		StringBuilder url = new StringBuilder(fragment ? redirectUri : fragments[0]);

		char separator = fragment ? '#' : '?';
		if (redirectUri.indexOf(separator) < 0) {
			url.append(separator);
		}
		else {
			url.append('&');
		}
		url.append("error=").append(failure.getOAuth2ErrorCode());
		try {

			url.append("&error_description=").append(URLEncoder.encode(failure.getMessage(), "UTF-8"));

			if (authorizationRequest.getState() != null) {
				url.append('&').append("state=").append(authorizationRequest.getState());
			}

			if (failure.getAdditionalInformation() != null) {
				for (Map.Entry<String, String> additionalInfo : failure.getAdditionalInformation().entrySet()) {
					url.append('&').append(additionalInfo.getKey()).append('=')
							.append(URLEncoder.encode(additionalInfo.getValue(), "UTF-8"));
				}
			}

		}
		catch (UnsupportedEncodingException e) {
			throw new IllegalStateException(e);
		}

		if (!fragment && fragments.length > 1) {
			url.append("#" + fragments[1]);
		}

		return url.toString();

	}

	public void setUserApprovalPage(String userApprovalPage) {
		this.userApprovalPage = userApprovalPage;
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

	@ExceptionHandler(OAuth2Exception.class)
	public ModelAndView handleOAuth2Exception(OAuth2Exception e, ServletWebRequest webRequest) throws Exception {
		logger.info("OAuth2 error" + e.getSummary());
		return handleException(e, webRequest);
	}

	@ExceptionHandler(HttpSessionRequiredException.class)
	public ModelAndView handleHttpSessionRequiredException(HttpSessionRequiredException e, ServletWebRequest webRequest)
			throws Exception {
		logger.info("Session required error: " + e.getMessage());
		return handleException(new AccessDeniedException("Could not obtain authorization request from session", e),
				webRequest);
	}

	private ModelAndView handleException(Exception e, ServletWebRequest webRequest) throws Exception {
		ResponseEntity<OAuth2Exception> translate = getExceptionTranslator().translate(e);
		webRequest.getResponse().setStatus(translate.getStatusCode().value());
		return new ModelAndView(errorPage, Collections.singletonMap("error", translate.getBody()));
	}
}
