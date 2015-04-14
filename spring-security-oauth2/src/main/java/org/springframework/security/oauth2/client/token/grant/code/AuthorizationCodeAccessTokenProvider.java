/*
 * Copyright 2002-2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * Copyright 2002-2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.client.token.grant.code;

import java.io.IOException;
import java.net.URI;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.client.filter.state.DefaultStateKeyGenerator;
import org.springframework.security.oauth2.client.filter.state.StateKeyGenerator;
import org.springframework.security.oauth2.client.resource.OAuth2AccessDeniedException;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.resource.UserApprovalRequiredException;
import org.springframework.security.oauth2.client.resource.UserRedirectRequiredException;
import org.springframework.security.oauth2.client.token.AccessTokenProvider;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.DefaultRequestEnhancer;
import org.springframework.security.oauth2.client.token.OAuth2AccessTokenSupport;
import org.springframework.security.oauth2.client.token.RequestEnhancer;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.ResponseExtractor;

/**
 * Provider for obtaining an oauth2 access token by using an authorization code.
 * 
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class AuthorizationCodeAccessTokenProvider extends OAuth2AccessTokenSupport implements AccessTokenProvider {

	private StateKeyGenerator stateKeyGenerator = new DefaultStateKeyGenerator();

	private String scopePrefix = OAuth2Utils.SCOPE_PREFIX;

	private RequestEnhancer authorizationRequestEnhancer = new DefaultRequestEnhancer();

	private boolean stateMandatory = true;
	
	/**
	 * Flag to say that the use of state parameter is mandatory.
	 * 
	 * @param stateMandatory the flag value (default true)
	 */
	public void setStateMandatory(boolean stateMandatory) {
		this.stateMandatory = stateMandatory;
	}

	/**
	 * A custom enhancer for the authorization request
	 * @param authorizationRequestEnhancer
	 */
	public void setAuthorizationRequestEnhancer(RequestEnhancer authorizationRequestEnhancer) {
		this.authorizationRequestEnhancer = authorizationRequestEnhancer;
	}

	/**
	 * Prefix for scope approval parameters.
	 * 
	 * @param scopePrefix
	 */
	public void setScopePrefix(String scopePrefix) {
		this.scopePrefix = scopePrefix;
	}

	/**
	 * @param stateKeyGenerator the stateKeyGenerator to set
	 */
	public void setStateKeyGenerator(StateKeyGenerator stateKeyGenerator) {
		this.stateKeyGenerator = stateKeyGenerator;
	}

	public boolean supportsResource(OAuth2ProtectedResourceDetails resource) {
		return resource instanceof AuthorizationCodeResourceDetails
				&& "authorization_code".equals(resource.getGrantType());
	}

	public boolean supportsRefresh(OAuth2ProtectedResourceDetails resource) {
		return supportsResource(resource);
	}

	public String obtainAuthorizationCode(OAuth2ProtectedResourceDetails details, AccessTokenRequest request)
			throws UserRedirectRequiredException, UserApprovalRequiredException, AccessDeniedException,
			OAuth2AccessDeniedException {

		AuthorizationCodeResourceDetails resource = (AuthorizationCodeResourceDetails) details;

		HttpHeaders headers = getHeadersForAuthorizationRequest(request);
		MultiValueMap<String, String> form = new LinkedMultiValueMap<String, String>();
		if (request.containsKey(OAuth2Utils.USER_OAUTH_APPROVAL)) {
			form.set(OAuth2Utils.USER_OAUTH_APPROVAL, request.getFirst(OAuth2Utils.USER_OAUTH_APPROVAL));
			for (String scope : details.getScope()) {
				form.set(scopePrefix + scope, request.getFirst(OAuth2Utils.USER_OAUTH_APPROVAL));
			}
		}
		else {
			form.putAll(getParametersForAuthorizeRequest(resource, request));
		}
		authorizationRequestEnhancer.enhance(request, resource, form, headers);
		final AccessTokenRequest copy = request;

		final ResponseExtractor<ResponseEntity<Void>> delegate = getAuthorizationResponseExtractor();
		ResponseExtractor<ResponseEntity<Void>> extractor = new ResponseExtractor<ResponseEntity<Void>>() {
			@Override
			public ResponseEntity<Void> extractData(ClientHttpResponse response) throws IOException {
				if (response.getHeaders().containsKey("Set-Cookie")) {
					copy.setCookie(response.getHeaders().getFirst("Set-Cookie"));
				}
				return delegate.extractData(response);
			}
		};
		// Instead of using restTemplate.exchange we use an explicit response extractor here so it can be overridden by
		// subclasses
		ResponseEntity<Void> response = getRestTemplate().execute(resource.getUserAuthorizationUri(), HttpMethod.POST,
				getRequestCallback(resource, form, headers), extractor, form.toSingleValueMap());

		if (response.getStatusCode() == HttpStatus.OK) {
			// Need to re-submit with approval...
			throw getUserApprovalSignal(resource, request);
		}

		URI location = response.getHeaders().getLocation();
		String query = location.getQuery();
		Map<String, String> map = OAuth2Utils.extractMap(query);
		if (map.containsKey("state")) {
			request.setStateKey(map.get("state"));
			if (request.getPreservedState() == null) {
				String redirectUri = resource.getRedirectUri(request);
				if (redirectUri != null) {
					request.setPreservedState(redirectUri);
				}
				else {
					request.setPreservedState(new Object());
				}
			}
		}

		String code = map.get("code");
		if (code == null) {
			throw new UserRedirectRequiredException(location.toString(), form.toSingleValueMap());
		}
		request.set("code", code);
		return code;

	}

	protected ResponseExtractor<ResponseEntity<Void>> getAuthorizationResponseExtractor() {
		return new ResponseExtractor<ResponseEntity<Void>>() {
			public ResponseEntity<Void> extractData(ClientHttpResponse response) throws IOException {
				return new ResponseEntity<Void>(response.getHeaders(), response.getStatusCode());
			}
		};
	}

	public OAuth2AccessToken obtainAccessToken(OAuth2ProtectedResourceDetails details, AccessTokenRequest request)
			throws UserRedirectRequiredException, UserApprovalRequiredException, AccessDeniedException,
			OAuth2AccessDeniedException {

		AuthorizationCodeResourceDetails resource = (AuthorizationCodeResourceDetails) details;

		if (request.getAuthorizationCode() == null) {
			if (request.getStateKey() == null) {
				throw getRedirectForAuthorization(resource, request);
			}
			obtainAuthorizationCode(resource, request);
		}
		return retrieveToken(request, resource, getParametersForTokenRequest(resource, request),
				getHeadersForTokenRequest(request));

	}

	public OAuth2AccessToken refreshAccessToken(OAuth2ProtectedResourceDetails resource,
			OAuth2RefreshToken refreshToken, AccessTokenRequest request) throws UserRedirectRequiredException,
			OAuth2AccessDeniedException {
		MultiValueMap<String, String> form = new LinkedMultiValueMap<String, String>();
		form.add("grant_type", "refresh_token");
		form.add("refresh_token", refreshToken.getValue());
		try {
			return retrieveToken(request, resource, form, getHeadersForTokenRequest(request));
		}
		catch (OAuth2AccessDeniedException e) {
			throw getRedirectForAuthorization((AuthorizationCodeResourceDetails) resource, request);
		}
	}

	private HttpHeaders getHeadersForTokenRequest(AccessTokenRequest request) {
		HttpHeaders headers = new HttpHeaders();
		// No cookie for token request
		return headers;
	}

	private HttpHeaders getHeadersForAuthorizationRequest(AccessTokenRequest request) {
		HttpHeaders headers = new HttpHeaders();
		headers.putAll(request.getHeaders());
		if (request.getCookie() != null) {
			headers.set("Cookie", request.getCookie());
		}
		return headers;
	}

	private MultiValueMap<String, String> getParametersForTokenRequest(AuthorizationCodeResourceDetails resource,
			AccessTokenRequest request) {

		MultiValueMap<String, String> form = new LinkedMultiValueMap<String, String>();
		form.set("grant_type", "authorization_code");
		form.set("code", request.getAuthorizationCode());

		Object preservedState = request.getPreservedState();
		if (request.getStateKey() != null || stateMandatory) {
			// The token endpoint has no use for the state so we don't send it back, but we are using it
			// for CSRF detection client side...
			if (preservedState == null) {
				throw new InvalidRequestException(
						"Possible CSRF detected - state parameter was required but no state could be found");
			}
		}

		// Extracting the redirect URI from a saved request should ignore the current URI, so it's not simply a call to
		// resource.getRedirectUri()
		String redirectUri = null;
		// Get the redirect uri from the stored state
		if (preservedState instanceof String) {
			// Use the preserved state in preference if it is there
			// TODO: treat redirect URI as a special kind of state (this is a historical mini hack)
			redirectUri = String.valueOf(preservedState);
		}
		else {
			redirectUri = resource.getRedirectUri(request);
		}

		if (redirectUri != null && !"NONE".equals(redirectUri)) {
			form.set("redirect_uri", redirectUri);
		}

		return form;

	}

	private MultiValueMap<String, String> getParametersForAuthorizeRequest(AuthorizationCodeResourceDetails resource,
			AccessTokenRequest request) {

		MultiValueMap<String, String> form = new LinkedMultiValueMap<String, String>();
		form.set("response_type", "code");
		form.set("client_id", resource.getClientId());

		if (request.get("scope") != null) {
			form.set("scope", request.getFirst("scope"));
		}
		else {
			form.set("scope", OAuth2Utils.formatParameterList(resource.getScope()));
		}

		// Extracting the redirect URI from a saved request should ignore the current URI, so it's not simply a call to
		// resource.getRedirectUri()
		String redirectUri = resource.getPreEstablishedRedirectUri();

		Object preservedState = request.getPreservedState();
		if (redirectUri == null && preservedState != null) {
			// no pre-established redirect uri: use the preserved state
			// TODO: treat redirect URI as a special kind of state (this is a historical mini hack)
			redirectUri = String.valueOf(preservedState);
		}
		else {
			redirectUri = request.getCurrentUri();
		}

		String stateKey = request.getStateKey();
		if (stateKey != null) {
			form.set("state", stateKey);
			if (preservedState == null) {
				throw new InvalidRequestException(
						"Possible CSRF detected - state parameter was present but no state could be found");
			}
		}

		if (redirectUri != null) {
			form.set("redirect_uri", redirectUri);
		}

		return form;

	}

	private UserRedirectRequiredException getRedirectForAuthorization(AuthorizationCodeResourceDetails resource,
			AccessTokenRequest request) {

		// we don't have an authorization code yet. So first get that.
		TreeMap<String, String> requestParameters = new TreeMap<String, String>();
		requestParameters.put("response_type", "code"); // oauth2 spec, section 3
		requestParameters.put("client_id", resource.getClientId());
		// Client secret is not required in the initial authorization request

		String redirectUri = resource.getRedirectUri(request);
		if (redirectUri != null) {
			requestParameters.put("redirect_uri", redirectUri);
		}

		if (resource.isScoped()) {

			StringBuilder builder = new StringBuilder();
			List<String> scope = resource.getScope();

			if (scope != null) {
				Iterator<String> scopeIt = scope.iterator();
				while (scopeIt.hasNext()) {
					builder.append(scopeIt.next());
					if (scopeIt.hasNext()) {
						builder.append(' ');
					}
				}
			}

			requestParameters.put("scope", builder.toString());
		}

		UserRedirectRequiredException redirectException = new UserRedirectRequiredException(
				resource.getUserAuthorizationUri(), requestParameters);

		String stateKey = stateKeyGenerator.generateKey(resource);
		redirectException.setStateKey(stateKey);
		request.setStateKey(stateKey);
		redirectException.setStateToPreserve(redirectUri);
		request.setPreservedState(redirectUri);

		return redirectException;

	}

	protected UserApprovalRequiredException getUserApprovalSignal(AuthorizationCodeResourceDetails resource,
			AccessTokenRequest request) {
		String message = String.format("Do you approve the client '%s' to access your resources with scope=%s",
				resource.getClientId(), resource.getScope());
		return new UserApprovalRequiredException(resource.getUserAuthorizationUri(), Collections.singletonMap(
				OAuth2Utils.USER_OAUTH_APPROVAL, message), resource.getClientId(), resource.getScope());
	}

}
