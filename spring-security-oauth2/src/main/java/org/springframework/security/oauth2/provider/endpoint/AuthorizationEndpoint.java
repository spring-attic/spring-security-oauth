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

import static org.springframework.security.oauth2.provider.OAuth2Request.REDIRECT_URI;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.Principal;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.BadClientCredentialsException;
import org.springframework.security.oauth2.common.exceptions.ClientAuthenticationException;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.common.exceptions.RedirectMismatchException;
import org.springframework.security.oauth2.common.exceptions.UnapprovedClientAuthenticationException;
import org.springframework.security.oauth2.common.exceptions.UnsupportedResponseTypeException;
import org.springframework.security.oauth2.common.exceptions.UserDeniedAuthorizationException;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.oauth2.provider.approval.DefaultUserApprovalHandler;
import org.springframework.security.oauth2.provider.approval.UserApprovalHandler;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.AuthorizationRequestHolder;
import org.springframework.security.oauth2.provider.code.InMemoryAuthorizationCodeServices;
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
import org.springframework.web.servlet.view.RedirectView;
import org.springframework.web.util.UriTemplate;

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

	/**
	 * 
	 */
	private static final String ORIGINAL_SCOPE = "original_scope";

	private AuthorizationCodeServices authorizationCodeServices = new InMemoryAuthorizationCodeServices();

	private RedirectResolver redirectResolver = new DefaultRedirectResolver();

	private UserApprovalHandler userApprovalHandler = new DefaultUserApprovalHandler();

	private SessionAttributeStore sessionAttributeStore = new DefaultSessionAttributeStore();

	private String userApprovalPage = "forward:/oauth/confirm_access";

	private String errorPage = "forward:/oauth/error";

	public void afterPropertiesSet() throws Exception {
		super.afterPropertiesSet();
	}

	public void setSessionAttributeStore(SessionAttributeStore sessionAttributeStore) {
		this.sessionAttributeStore = sessionAttributeStore;
	}

	public void setErrorPage(String errorPage) {
		this.errorPage = errorPage;
	}

	@RequestMapping
	public ModelAndView authorize(Map<String, Object> model, @RequestParam Map<String, String> parameters, 
			SessionStatus sessionStatus, Principal principal) {

		//Pull out the authorization request first, using the authorization request manager. All further logic should
		//query off of the authorization request instead of referring back to the parameters map. The contents of the 
		//parameters map will be stored without change in the AuthorizationRequest object once it is created.
		OAuth2Request oAuth2Request = getOAuth2RequestManager().createOAuth2Request(parameters);

		Set<String> responseTypes = oAuth2Request.getResponseTypes();

		if (!responseTypes.contains("token") && !responseTypes.contains("code")) {
			throw new UnsupportedResponseTypeException("Unsupported response types: " + responseTypes);
		}

		if (oAuth2Request.getClientId() == null) {
			throw new InvalidClientException("A client id must be provided");
		}
		
		try {
			
			if (!(principal instanceof Authentication) || !((Authentication) principal).isAuthenticated()) {
				throw new InsufficientAuthenticationException(
						"User must be authenticated with Spring Security before authorization can be completed.");
			}

			// The resolved redirect URI is either the redirect_uri from the parameters or the one from
			// clientDetails. Either way we need to store it on the AuthorizationRequest.
			String redirectUriParameter = oAuth2Request.getRequestParameters().get(OAuth2Request.REDIRECT_URI);
			String resolvedRedirect = redirectResolver.resolveRedirect(redirectUriParameter, getClientDetailsService()
					.loadClientByClientId(oAuth2Request.getClientId()));
			if (!StringUtils.hasText(resolvedRedirect)) {
				throw new RedirectMismatchException(
						"A redirectUri must be either supplied or preconfigured in the ClientDetails");
			}
			oAuth2Request.setRedirectUri(resolvedRedirect);

			// We intentionally only validate the parameters requested by the client (ignoring any data that may have
			// been added to the request by the manager).
			getOAuth2RequestManager().validateParameters(oAuth2Request.getRequestParameters(),
					getClientDetailsService().loadClientByClientId(oAuth2Request.getClientId()));

			//Some systems may allow for approval decisions to be remembered or approved by default. Check for 
			//such logic here, and set the approved flag on the authorization request accordingly.
			oAuth2Request = userApprovalHandler.checkForPreApproval(oAuth2Request, (Authentication) principal);
			boolean approved = userApprovalHandler.isApproved(oAuth2Request, (Authentication) principal);
			oAuth2Request.setApproved(approved);
			
			// Validation is all done, so we can check for auto approval...
			if (oAuth2Request.isApproved()) {
				if (responseTypes.contains("token")) {
					return getImplicitGrantResponse(oAuth2Request);
				}
				if (responseTypes.contains("code")) {
					return new ModelAndView(getAuthorizationCodeResponse(oAuth2Request, (Authentication) principal));
				}
			}

			// Place auth request into the model so that it is stored in the session
			// for approveOrDeny to use. That way we make sure that auth request comes from the session,
			// so any auth request parameters passed to approveOrDeny will be ignored and retrieved from the session.
			model.put("authorizationRequest", oAuth2Request);

			return getUserApprovalPageResponse(model, oAuth2Request);

		}
		catch (RuntimeException e) {
			sessionStatus.setComplete();
			throw e;
		}

	}

	@RequestMapping(method = RequestMethod.POST, params = OAuth2Request.USER_OAUTH_APPROVAL)
	public View approveOrDeny(@RequestParam Map<String, String> approvalParameters, Map<String, ?> model,
			SessionStatus sessionStatus, Principal principal) {

		if (!(principal instanceof Authentication)) {
			sessionStatus.setComplete();
			throw new InsufficientAuthenticationException(
					"User must be authenticated with Spring Security before authorizing an access token.");
		}

		OAuth2Request oAuth2Request = (OAuth2Request) model.get("authorizationRequest");

		if (oAuth2Request == null) {
			sessionStatus.setComplete();
			throw new InvalidRequestException("Cannot approve uninitialized authorization request.");
		}

		try {
			Set<String> responseTypes = oAuth2Request.getResponseTypes();

			oAuth2Request.setApprovalParameters(approvalParameters);
			oAuth2Request = userApprovalHandler.updateAfterApproval(oAuth2Request, (Authentication) principal);
			boolean approved = userApprovalHandler.isApproved(oAuth2Request, (Authentication) principal);
			oAuth2Request.setApproved(approved);

			if (oAuth2Request.getRedirectUri() == null) {
				sessionStatus.setComplete();
				throw new InvalidRequestException("Cannot approve request when no redirect URI is provided.");
			}
			
			if (!oAuth2Request.isApproved()) {
				return new RedirectView(getUnsuccessfulRedirect(oAuth2Request, new UserDeniedAuthorizationException(
						"User denied access"), responseTypes.contains("token")), false);
			}

			if (responseTypes.contains("token")) {
				return getImplicitGrantResponse(oAuth2Request).getView();
			}

			return getAuthorizationCodeResponse(oAuth2Request, (Authentication) principal);
		}
		finally {
			sessionStatus.setComplete();
		}

	}

	// We need explicit approval from the user.
	private ModelAndView getUserApprovalPageResponse(Map<String, Object> model,
			OAuth2Request oAuth2Request) {
		logger.debug("Loading user approval page: " + userApprovalPage);
		// In case of a redirect we might want the request parameters to be included
		model.putAll(oAuth2Request.getRequestParameters());
		return new ModelAndView(userApprovalPage, model);
	}

	// We can grant a token and return it with implicit approval.
	private ModelAndView getImplicitGrantResponse(OAuth2Request oAuth2Request) {
		try {
			OAuth2AccessToken accessToken = getTokenGranter().grant("implicit", oAuth2Request);
			if (accessToken == null) {
				throw new UnsupportedResponseTypeException("Unsupported response type: token");
			}
			return new ModelAndView(new RedirectView(appendAccessToken(oAuth2Request, accessToken), false));
		}
		catch (OAuth2Exception e) {
			return new ModelAndView(new RedirectView(getUnsuccessfulRedirect(oAuth2Request, e, true), false));
		}
	}

	private View getAuthorizationCodeResponse(OAuth2Request oAuth2Request, Authentication authUser) {
		try {
			return new RedirectView(getSuccessfulRedirect(oAuth2Request,
					generateCode(oAuth2Request, authUser)), false);
		}
		catch (OAuth2Exception e) {
			return new RedirectView(getUnsuccessfulRedirect(oAuth2Request, e, false), false);
		}
	}
   
	private String appendAccessToken(OAuth2Request oAuth2Request, OAuth2AccessToken accessToken) {
        
        Map<String, Object> vars = new HashMap<String, Object>();
        
		String requestedRedirect = oAuth2Request.getRedirectUri();
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

		url.append("access_token={access_token}");
		url.append("&token_type={token_type}");
		vars.put("access_token", accessToken.getValue());
		vars.put("token_type", accessToken.getTokenType());
		String state = oAuth2Request.getState();
        
		if (state != null) {
			url.append("&state={state}");
			vars.put("state", state);
		}
		Date expiration = accessToken.getExpiration();
		if (expiration != null) {
			long expires_in = (expiration.getTime() - System.currentTimeMillis()) / 1000;
			url.append("&expires_in={expires_in}");
			vars.put("expires_in", expires_in);
		}
		String originalScope = authorizationRequest.getAuthorizationParameters().get(ORIGINAL_SCOPE);
		if (originalScope==null || !OAuth2Utils.parseParameterList(originalScope).equals(accessToken.getScope())) {
			url.append("&" + AuthorizationRequest.SCOPE + "={scope}");
			vars.put("scope", OAuth2Utils.formatParameterList(accessToken.getScope()));
		}
		Map<String, Object> additionalInformation = accessToken.getAdditionalInformation();
		for (String key : additionalInformation.keySet()) {
			Object value = additionalInformation.get(key);
			if (value != null) {
				url.append("&" + key + "={extra_" + key + "}");
				vars.put("extra_" + key, value);
			}
		}
		UriTemplate template = new UriTemplate(url.toString());
		// Do not include the refresh token (even if there is one)
		return template.expand(vars).toString();
	}

	private String generateCode(OAuth2Request oAuth2Request, Authentication authentication)
			throws AuthenticationException {

		try {

			AuthorizationRequestHolder combinedAuth = new AuthorizationRequestHolder(oAuth2Request,
					authentication);
			String code = authorizationCodeServices.createAuthorizationCode(combinedAuth);

			return code;

		}
		catch (OAuth2Exception e) {

			if (oAuth2Request.getState() != null) {
				e.addAdditionalInformation("state", oAuth2Request.getState());
			}

			throw e;

		}
	}

	private String getSuccessfulRedirect(OAuth2Request oAuth2Request, String authorizationCode) {

		if (authorizationCode == null) {
			throw new IllegalStateException("No authorization code found in the current request scope.");
		}

		String requestedRedirect = oAuth2Request.getRedirectUri();
		String[] fragments = requestedRedirect.split("#");
		String state = oAuth2Request.getState();

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

	private String getUnsuccessfulRedirect(OAuth2Request oAuth2Request, OAuth2Exception failure,
			boolean fragment) {

		if (oAuth2Request == null || oAuth2Request.getRedirectUri() == null) {
			// we have no redirect for the user. very sad.
			throw new UnapprovedClientAuthenticationException("Authorization failure, and no redirect URI.", failure);
		}

		String redirectUri = oAuth2Request.getRedirectUri();

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

			if (oAuth2Request.getState() != null) {
				url.append('&').append("state=").append(oAuth2Request.getState());
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

		OAuth2Request oAuth2Request = null;
		try {
			oAuth2Request = getOAuth2RequestForError(webRequest);
			String requestedRedirectParam = oAuth2Request.getRequestParameters().get(REDIRECT_URI);
			String requestedRedirect = redirectResolver.resolveRedirect(requestedRedirectParam,
					getClientDetailsService().loadClientByClientId(oAuth2Request.getClientId()));
			oAuth2Request.setRedirectUri(requestedRedirect);
			String redirect = getUnsuccessfulRedirect(oAuth2Request, translate.getBody(), oAuth2Request
					.getResponseTypes().contains("token"));
			return new ModelAndView(new RedirectView(redirect, false));
		}
		catch (OAuth2Exception ex) {
			// If an AuthorizationRequest cannot be created from the incoming parameters it must be
			// an error. OAuth2Exception can be handled this way. Other exceptions will generate a standard 500
			// response.
			return new ModelAndView(errorPage, Collections.singletonMap("error", translate.getBody()));
		}

	}

	private OAuth2Request getOAuth2RequestForError(ServletWebRequest webRequest) {

		// If it's already there then we are in the approveOrDeny phase and we can use the saved request
		OAuth2Request oAuth2Request = (OAuth2Request) sessionAttributeStore.retrieveAttribute(
				webRequest, "authorizationRequest");
		if (oAuth2Request != null) {
			return oAuth2Request;
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
			return getOAuth2RequestManager().createOAuth2Request(parameters);
		}
		catch (Exception e) {
			return getDefaultOAuth2RequestManager().createOAuth2Request(parameters);
		}

	}
}
