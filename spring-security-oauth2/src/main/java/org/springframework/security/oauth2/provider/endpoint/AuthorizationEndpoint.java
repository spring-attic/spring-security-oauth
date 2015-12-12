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
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.exceptions.BadClientCredentialsException;
import org.springframework.security.oauth2.common.exceptions.ClientAuthenticationException;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.common.exceptions.RedirectMismatchException;
import org.springframework.security.oauth2.common.exceptions.UnsupportedResponseTypeException;
import org.springframework.security.oauth2.common.exceptions.UserDeniedAuthorizationException;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.oauth2.provider.OAuth2RequestValidator;
import org.springframework.security.oauth2.provider.approval.DefaultUserApprovalHandler;
import org.springframework.security.oauth2.provider.approval.UserApprovalHandler;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.InMemoryAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestValidator;
import org.springframework.security.oauth2.provider.response.DefaultAuthorizationRequestViewResolver;
import org.springframework.security.oauth2.provider.response.AuthorizationRequestViewResolver;
import org.springframework.security.oauth2.provider.response.ResponseTypesHandler;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.HttpSessionRequiredException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.bind.support.DefaultSessionAttributeStore;
import org.springframework.web.bind.support.SessionAttributeStore;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.View;

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
public class AuthorizationEndpoint extends AbstractEndpoint {

	private AuthorizationCodeServices authorizationCodeServices = new InMemoryAuthorizationCodeServices();

	private RedirectResolver redirectResolver = new DefaultRedirectResolver();

	private UserApprovalHandler userApprovalHandler = new DefaultUserApprovalHandler();

	private SessionAttributeStore sessionAttributeStore = new DefaultSessionAttributeStore();

	private OAuth2RequestValidator oauth2RequestValidator = new DefaultOAuth2RequestValidator();

	private AuthorizationRequestViewResolver authorizationRequestViewResolver = new DefaultAuthorizationRequestViewResolver();

	private ResponseTypesHandler responseTypesHandler;

	private String userApprovalPage = "forward:/oauth/confirm_access";

	private String errorPage = "forward:/oauth/error";

	public void setErrorPage(String errorPage) {
		this.errorPage = errorPage;
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		super.afterPropertiesSet();
		Assert.state(responseTypesHandler != null, "ResponseTypesHandler must be provided");
	}

	@RequestMapping(value = "/oauth/authorize")
	public ModelAndView authorize(Map<String, Object> model, @RequestParam Map<String, String> parameters,
			SessionStatus sessionStatus, Principal principal) {

		// Pull out the authorization request first, using the OAuth2RequestFactory. All further logic should
		// query off of the authorization request instead of referring back to the parameters map. The contents of the
		// parameters map will be stored without change in the AuthorizationRequest object once it is created.
		AuthorizationRequest authorizationRequest = getOAuth2RequestFactory().createAuthorizationRequest(parameters);

		Set<String> responseTypes = authorizationRequest.getResponseTypes();

		//fail fast if the ResponseTypesHandler can't handle the responseTypes
		if (!responseTypesHandler.canHandleResponseTypes(responseTypes)) {
			throw new UnsupportedResponseTypeException("Unsupported response types: " + responseTypes);
		}

		if (authorizationRequest.getClientId() == null) {
			throw new InvalidClientException("A client id must be provided");
		}

		try {

			if (!(principal instanceof Authentication) || !((Authentication) principal).isAuthenticated()) {
				throw new InsufficientAuthenticationException(
						"User must be authenticated with Spring Security before authorization can be completed.");
			}
			Authentication authentication = (Authentication) principal;

			ClientDetails client = getClientDetailsService().loadClientByClientId(authorizationRequest.getClientId());

			// The resolved redirect URI is either the redirect_uri from the parameters or the one from
			// clientDetails. Either way we need to store it on the AuthorizationRequest.
			String redirectUriParameter = authorizationRequest.getRequestParameters().get(OAuth2Utils.REDIRECT_URI);
			String resolvedRedirect = redirectResolver.resolveRedirect(redirectUriParameter, client);
			if (!StringUtils.hasText(resolvedRedirect)) {
				throw new RedirectMismatchException(
						"A redirectUri must be either supplied or preconfigured in the ClientDetails");
			}
			authorizationRequest.setRedirectUri(resolvedRedirect);

			// We intentionally only validate the parameters requested by the client (ignoring any data that may have
			// been added to the request by the manager).
			oauth2RequestValidator.validateScope(authorizationRequest, client);

			// Some systems may allow for approval decisions to be remembered or approved by default. Check for
			// such logic here, and set the approved flag on the authorization request accordingly.
			authorizationRequest = userApprovalHandler.checkForPreApproval(authorizationRequest,
					(Authentication) principal);
			// TODO: is this call necessary?
			boolean approved = userApprovalHandler.isApproved(authorizationRequest, authentication);
			authorizationRequest.setApproved(approved);

			// Validation is all done, so we can check for auto approval...
			if (authorizationRequest.isApproved()) {
					//We would have not gotten this far if the customResponseTypesHandler could not handle this
					return responseTypesHandler.handleApprovedAuthorizationRequest(responseTypes,
							authorizationRequest, authentication, authorizationCodeServices);
			}

			// Place auth request into the model so that it is stored in the session
			// for approveOrDeny to use. That way we make sure that auth request comes from the session,
			// so any auth request parameters passed to approveOrDeny will be ignored and retrieved from the session.
			model.put("authorizationRequest", authorizationRequest);

			return getUserApprovalPageResponse(model, authorizationRequest, authentication);

		}
		catch (RuntimeException e) {
			sessionStatus.setComplete();
			throw e;
		}

	}

	@RequestMapping(value = "/oauth/authorize", method = RequestMethod.POST, params = OAuth2Utils.USER_OAUTH_APPROVAL)
	public View approveOrDeny(@RequestParam Map<String, String> approvalParameters, Map<String, ?> model,
			SessionStatus sessionStatus, Principal principal) {

		if (!(principal instanceof Authentication)) {
			sessionStatus.setComplete();
			throw new InsufficientAuthenticationException(
					"User must be authenticated with Spring Security before authorizing an access token.");
		}

		AuthorizationRequest authorizationRequest = (AuthorizationRequest) model.get("authorizationRequest");

		if (authorizationRequest == null) {
			sessionStatus.setComplete();
			throw new InvalidRequestException("Cannot approve uninitialized authorization request.");
		}

		try {
			Set<String> responseTypes = authorizationRequest.getResponseTypes();

			if (!responseTypesHandler.canHandleResponseTypes(responseTypes)) {
				throw new UnsupportedResponseTypeException("Unsupported response types: " + responseTypes);
			}

			authorizationRequest.setApprovalParameters(approvalParameters);
			authorizationRequest = userApprovalHandler.updateAfterApproval(authorizationRequest,
					(Authentication) principal);
			boolean approved = userApprovalHandler.isApproved(authorizationRequest, (Authentication) principal);
			authorizationRequest.setApproved(approved);

			if (authorizationRequest.getRedirectUri() == null) {
				sessionStatus.setComplete();
				throw new InvalidRequestException("Cannot approve request when no redirect URI is provided.");
			}

			if (!authorizationRequest.isApproved()) {
				return authorizationRequestViewResolver.getUnsuccessfulView(authorizationRequest,
						new UserDeniedAuthorizationException("User denied access"));
			}
			return responseTypesHandler.handleApprovedAuthorizationRequest(responseTypes, authorizationRequest,
					(Authentication) principal, authorizationCodeServices).getView();
		}
		finally {
			sessionStatus.setComplete();
		}

	}

	// We need explicit approval from the user.
	private ModelAndView getUserApprovalPageResponse(Map<String, Object> model,
			AuthorizationRequest authorizationRequest, Authentication principal) {
		logger.debug("Loading user approval page: " + userApprovalPage);
		model.putAll(userApprovalHandler.getUserApprovalRequest(authorizationRequest, principal));
		return new ModelAndView(userApprovalPage, model);
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

	public void setOAuth2RequestValidator(OAuth2RequestValidator oauth2RequestValidator) {
		this.oauth2RequestValidator = oauth2RequestValidator;
	}

	public void setResponseTypesHandler(ResponseTypesHandler responseTypesHandler) {
		this.responseTypesHandler = responseTypesHandler;
	}

	public void setSessionAttributeStore(SessionAttributeStore sessionAttributeStore) {
		this.sessionAttributeStore = sessionAttributeStore;
	}

	public void setAuthorizationRequestViewResolver(AuthorizationRequestViewResolver authorizationRequestViewResolver) {
		this.authorizationRequestViewResolver = authorizationRequestViewResolver;
	}

	@SuppressWarnings("deprecation")
	public void setImplicitGrantService(
			org.springframework.security.oauth2.provider.implicit.ImplicitGrantService implicitGrantService) {
	}

	@ExceptionHandler(ClientRegistrationException.class)
	public ModelAndView handleClientRegistrationException(Exception e, ServletWebRequest webRequest) throws Exception {
		logger.info("Handling ClientRegistrationException error: " + e.getMessage());
		return handleException(new BadClientCredentialsException(), webRequest);
	}

	@ExceptionHandler(OAuth2Exception.class)
	public ModelAndView handleOAuth2Exception(OAuth2Exception e, ServletWebRequest webRequest) throws Exception {
		logger.info("Handling OAuth2 error: " + e.getSummary());
		return handleException(e, webRequest);
	}

	@ExceptionHandler(HttpSessionRequiredException.class)
	public ModelAndView handleHttpSessionRequiredException(HttpSessionRequiredException e, ServletWebRequest webRequest)
			throws Exception {
		logger.info("Handling Session required error: " + e.getMessage());
		return handleException(new AccessDeniedException("Could not obtain authorization request from session", e),
				webRequest);
	}

	private ModelAndView handleException(Exception e, ServletWebRequest webRequest) throws Exception {

		ResponseEntity<OAuth2Exception> translate = getExceptionTranslator().translate(e);
		webRequest.getResponse().setStatus(translate.getStatusCode().value());

		if (e instanceof ClientAuthenticationException || e instanceof RedirectMismatchException) {
			return new ModelAndView(errorPage, Collections.singletonMap("error", translate.getBody()));
		}

		AuthorizationRequest authorizationRequest = null;
		try {
			authorizationRequest = getAuthorizationRequestForError(webRequest);
			String requestedRedirectParam = authorizationRequest.getRequestParameters().get(OAuth2Utils.REDIRECT_URI);
			String requestedRedirect = redirectResolver.resolveRedirect(requestedRedirectParam,
					getClientDetailsService().loadClientByClientId(authorizationRequest.getClientId()));
			authorizationRequest.setRedirectUri(requestedRedirect);
			View view = authorizationRequestViewResolver.getUnsuccessfulView(authorizationRequest, translate.getBody());
			return new ModelAndView(view);
		}
		catch (OAuth2Exception ex) {
			// If an AuthorizationRequest cannot be created from the incoming parameters it must be
			// an error. OAuth2Exception can be handled this way. Other exceptions will generate a standard 500
			// response.
			return new ModelAndView(errorPage, Collections.singletonMap("error", translate.getBody()));
		}

	}

	private AuthorizationRequest getAuthorizationRequestForError(ServletWebRequest webRequest) {

		// If it's already there then we are in the approveOrDeny phase and we can use the saved request
		AuthorizationRequest authorizationRequest = (AuthorizationRequest) sessionAttributeStore.retrieveAttribute(
				webRequest, "authorizationRequest");
		if (authorizationRequest != null) {
			return authorizationRequest;
		}

		Map<String, String> parameters = new HashMap<String, String>();
		Map<String, String[]> map = webRequest.getParameterMap();
		for (String key : map.keySet()) {
			String[] values = map.get(key);
			if (values != null && values.length > 0) {
				parameters.put(key, values[0]);
			}
		}

		try {
			return getOAuth2RequestFactory().createAuthorizationRequest(parameters);
		}
		catch (Exception e) {
			return getDefaultOAuth2RequestFactory().createAuthorizationRequest(parameters);
		}

	}
}
