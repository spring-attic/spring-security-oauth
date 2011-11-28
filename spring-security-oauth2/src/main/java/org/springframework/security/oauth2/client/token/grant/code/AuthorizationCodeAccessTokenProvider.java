package org.springframework.security.oauth2.client.token.grant.code;

import java.util.Iterator;
import java.util.List;
import java.util.TreeMap;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.client.UserRedirectRequiredException;
import org.springframework.security.oauth2.client.filter.state.DefaultStateKeyGenerator;
import org.springframework.security.oauth2.client.filter.state.StateKeyGenerator;
import org.springframework.security.oauth2.client.resource.OAuth2AccessDeniedException;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.AccessTokenProvider;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.OAuth2AccessTokenSupport;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

/**
 * Provider for obtaining an oauth2 access token by using an authorization code.
 * 
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class AuthorizationCodeAccessTokenProvider extends OAuth2AccessTokenSupport implements AccessTokenProvider {

	private StateKeyGenerator stateKeyGenerator = new DefaultStateKeyGenerator();
	
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

	public OAuth2AccessToken obtainAccessToken(OAuth2ProtectedResourceDetails details, AccessTokenRequest request)
			throws UserRedirectRequiredException, AccessDeniedException {

		AuthorizationCodeResourceDetails resource = (AuthorizationCodeResourceDetails) details;

		if (request.isError()) {

			// there was an oauth error...
			throw getSerializationService().deserializeError(request.toSingleValueMap());

		} else if (request.getAuthorizationCode() == null) {

			throw getRedirectForAuthorization(resource, request);

		} else {

			return retrieveToken(getParametersForTokenRequest(resource, request), resource);

		}

	}
	
	public OAuth2AccessToken refreshAccessToken(OAuth2ProtectedResourceDetails resource, OAuth2RefreshToken refreshToken, AccessTokenRequest request) throws UserRedirectRequiredException {
		MultiValueMap<String, String> form = new LinkedMultiValueMap<String, String>();
		form.add("grant_type", "refresh_token");
		form.add("refresh_token", refreshToken.getValue());
		try {
			return retrieveToken(form, resource);
		} catch (OAuth2AccessDeniedException e) {
			throw getRedirectForAuthorization((AuthorizationCodeResourceDetails) resource, request);
		}
	}

	private MultiValueMap<String, String> getParametersForTokenRequest(AuthorizationCodeResourceDetails resource,
			AccessTokenRequest request) {

		MultiValueMap<String, String> form = new LinkedMultiValueMap<String, String>();
		form.add("grant_type", "authorization_code");
		form.add("code", request.getAuthorizationCode());

		String redirectUri = resource.getPreEstablishedRedirectUri();
		if (redirectUri == null) {
			// no pre-established redirect uri: use the preserved state
			// TODO: treat redirect URI as a special kind of state (this is a historical mini hack)
			redirectUri = String.valueOf(request.getPreservedState());
		} else {
			// TODO: the state key is what should be sent, not the value
			form.add("state", String.valueOf(request.getPreservedState()));
		}

		if (redirectUri == null) {
			// still no redirect uri? just try the one for the current context...
			redirectUri = request == null ? null : request.getUserAuthorizationRedirectUri();
		}

		form.add("redirect_uri", redirectUri);

		return form;

	}

	private UserRedirectRequiredException getRedirectForAuthorization(AuthorizationCodeResourceDetails resource,
			AccessTokenRequest request) {

		// we don't have an authorization code yet. So first get that.
		TreeMap<String, String> requestParameters = new TreeMap<String, String>();
		requestParameters.put("response_type", "code"); // oauth2 spec, section 3
		requestParameters.put("client_id", resource.getClientId());
		// Client secret is not required in the initial authorization request
		
		String redirectUri = resource.getPreEstablishedRedirectUri();
		String userRedirectUri = request.getUserAuthorizationRedirectUri();
		if (redirectUri == null) {

			redirectUri = userRedirectUri;
			if (redirectUri == null) {
				throw new IllegalStateException(
						"No redirect URI has been established for the current request.");
			}
			requestParameters.put("redirect_uri", redirectUri);

		} else {

			redirectUri = null;

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
		if (stateKey != null) {
			redirectException.setStateKey(stateKey);
			if (userRedirectUri != null) {
				redirectException.setStateToPreserve(userRedirectUri);
			}
		}
		

		return redirectException;

	}

}
