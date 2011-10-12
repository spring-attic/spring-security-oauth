package org.springframework.security.oauth2.client.code;

import java.util.Iterator;
import java.util.List;
import java.util.TreeMap;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.client.*;
import org.springframework.security.oauth2.client.context.OAuth2ClientContext;
import org.springframework.security.oauth2.client.context.OAuth2ClientContextHolder;
import org.springframework.security.oauth2.client.provider.OAuth2AccessTokenSupport;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

/**
 * Provider for obtaining an oauth2 access token by using an authorization code.
 * 
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class AuthorizationCodeAccessTokenProvider extends OAuth2AccessTokenSupport implements OAuth2AccessTokenProvider {

	public boolean supportsResource(OAuth2ProtectedResourceDetails resource) {
		return resource instanceof AuthorizationCodeResourceDetails
				&& "authorization_code".equals(resource.getGrantType());
	}

	public OAuth2AccessToken obtainNewAccessToken(OAuth2ProtectedResourceDetails details)
			throws UserRedirectRequiredException, AccessDeniedException {

		AuthorizationCodeResourceDetails resource = (AuthorizationCodeResourceDetails) details;
		OAuth2ClientContext context = OAuth2ClientContextHolder.getContext();

		if (context != null && context.getErrorParameters() != null) {

			// there was an oauth error...
			throw getSerializationService().deserializeError(context.getErrorParameters());

		} else if (context==null || context.getAuthorizationCode() == null) {

			throw getRedirectForAuthorization(resource, context);

		} else {

			return retrieveToken(getParametersForTokenRequest(resource, context), resource);

		}

	}

	private MultiValueMap<String, String> getParametersForTokenRequest(AuthorizationCodeResourceDetails resource,
			OAuth2ClientContext context) {

		MultiValueMap<String, String> form = new LinkedMultiValueMap<String, String>();
		form.add("grant_type", "authorization_code");
		form.add("code", context.getAuthorizationCode());

		String redirectUri = resource.getPreEstablishedRedirectUri();
		if (context!=null && redirectUri == null) {
			// no pre-established redirect uri: use the preserved state
			// TODO: treat redirect URI as a special kind of state (this is a historical mini hack)
			redirectUri = String.valueOf(context.getPreservedState());
		} else {
			// TODO: the state key is what should be sent, not the value
			form.add("state", String.valueOf(context.getPreservedState()));
		}

		if (redirectUri == null) {
			// still no redirect uri? just try the one for the current context...
			redirectUri = context == null ? null : context.getUserAuthorizationRedirectUri();
		}

		form.add("redirect_uri", redirectUri);

		return form;

	}

	private UserRedirectRequiredException getRedirectForAuthorization(AuthorizationCodeResourceDetails resource,
			OAuth2ClientContext context) {

		// we don't have an authorization code yet. So first get that.
		TreeMap<String, String> requestParameters = new TreeMap<String, String>();
		requestParameters.put("response_type", "code"); // oauth2 spec, section 3
		requestParameters.put("client_id", resource.getClientId());
		// Client secret is not required in the initial authorization request
		
		String redirectUri = resource.getPreEstablishedRedirectUri();
		if (redirectUri == null) {

			if (context == null) {
				throw new IllegalStateException(
						"No OAuth 2 security context has been established: unable to determine the redirect URI for the current context.");
			}
			redirectUri = context.getUserAuthorizationRedirectUri();
			if (redirectUri == null) {
				throw new IllegalStateException(
						"No redirect URI has been established for the current OAuth 2 security context.");
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

		String stateKey = resource.getState();
		if (stateKey != null) {
			requestParameters.put("state", stateKey);
		}

		UserRedirectRequiredException redirectException = new UserRedirectRequiredException(
				resource.getUserAuthorizationUri(), requestParameters);

		if (redirectUri != null) {
			redirectException.setStateKey(resource.getState());
			redirectException.setStateToPreserve(redirectUri);
		}

		return redirectException;

	}

}
