package org.springframework.security.oauth2.client.provider.flow.client;

import java.util.Iterator;
import java.util.List;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.client.UserRedirectRequiredException;
import org.springframework.security.oauth2.client.context.OAuth2ClientContext;
import org.springframework.security.oauth2.client.context.OAuth2ClientContextHolder;
import org.springframework.security.oauth2.client.provider.OAuth2AccessTokenProvider;
import org.springframework.security.oauth2.client.provider.OAuth2AccessTokenSupport;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

/**
 * Provider for obtaining an oauth2 access token by using client credentials.
 * 
 * @author Dave Syer
 */
public class ClientCredentialsAccessTokenProvider extends OAuth2AccessTokenSupport implements OAuth2AccessTokenProvider {

	public boolean supportsResource(OAuth2ProtectedResourceDetails resource) {
		return resource instanceof ClientCredentialsResourceDetails
				&& "client_credentials".equals(resource.getGrantType());
	}

	public OAuth2AccessToken obtainNewAccessToken(OAuth2ProtectedResourceDetails details)
			throws UserRedirectRequiredException, AccessDeniedException {

		ClientCredentialsResourceDetails resource = (ClientCredentialsResourceDetails) details;
		OAuth2ClientContext context = OAuth2ClientContextHolder.getContext();

		if (context != null && context.getErrorParameters() != null) {

			// there was an oauth error...
			throw getSerializationService().deserializeError(context.getErrorParameters());

		} else {

			return retrieveToken(getParametersForTokenRequest(resource, context), resource);

		}

	}

	private MultiValueMap<String, String> getParametersForTokenRequest(ClientCredentialsResourceDetails resource,
			OAuth2ClientContext context) {

		MultiValueMap<String, String> form = new LinkedMultiValueMap<String, String>();
		form.add("grant_type", "client_credentials");

		String redirectUri = resource.getPreEstablishedRedirectUri();
		if (context != null && redirectUri == null && context.getPreservedState()!=null) {
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

			form.add("scope", builder.toString());
		}

		form.add("redirect_uri", redirectUri);
		form.add("client_id", resource.getClientId());
		if (resource.isSecretRequired()) {
			form.add("client_secret", resource.getClientSecret());
		}

		return form;

	}

}
