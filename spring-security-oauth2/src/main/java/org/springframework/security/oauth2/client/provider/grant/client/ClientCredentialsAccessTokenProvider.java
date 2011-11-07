package org.springframework.security.oauth2.client.provider.grant.client;

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

		return form;

	}

}
