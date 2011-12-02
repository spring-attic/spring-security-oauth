package org.springframework.security.oauth2.client.token.grant.password;

import java.util.Iterator;
import java.util.List;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.client.UserRedirectRequiredException;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.AccessTokenProvider;
import org.springframework.security.oauth2.client.token.OAuth2AccessTokenSupport;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

/**
 * Provider for obtaining an oauth2 access token by using resource owner password.
 * 
 * @author Dave Syer
 */
public class ResourceOwnerPasswordAccessTokenProvider extends OAuth2AccessTokenSupport implements AccessTokenProvider {

	public boolean supportsResource(OAuth2ProtectedResourceDetails resource) {
		return resource instanceof ResourceOwnerPasswordResourceDetails
				&& "password".equals(resource.getGrantType());
	}

	public boolean supportsRefresh(OAuth2ProtectedResourceDetails resource) {
		return false;
	}
	
	public OAuth2AccessToken refreshAccessToken(OAuth2ProtectedResourceDetails resource,
			OAuth2RefreshToken refreshToken, AccessTokenRequest request) throws UserRedirectRequiredException {
		return null;
	}

	public OAuth2AccessToken obtainAccessToken(OAuth2ProtectedResourceDetails details, AccessTokenRequest request)
			throws UserRedirectRequiredException, AccessDeniedException {

		if (request.isError()) {
			// there was an oauth error...
			throw getSerializationService().deserializeError(request.toSingleValueMap());
		} else {
			ResourceOwnerPasswordResourceDetails resource = (ResourceOwnerPasswordResourceDetails) details;
			return retrieveToken(getParametersForTokenRequest(resource), resource);
		}

	}

	private MultiValueMap<String, String> getParametersForTokenRequest(ResourceOwnerPasswordResourceDetails resource) {

		MultiValueMap<String, String> form = new LinkedMultiValueMap<String, String>();
		form.add("grant_type", "password");
		
		form.add("username", resource.getUsername());
		form.add("password", resource.getPassword());

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
