package org.springframework.security.oauth2.client.token.grant.implicit;

import java.io.IOException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.client.UserRedirectRequiredException;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.AccessTokenProvider;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.OAuth2AccessTokenSupport;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.client.ResponseExtractor;

/**
 * Provider for obtaining an oauth2 access token by using implicit grant. Normally the implicit grant is used by script
 * clients in a browser or device, but it can also be useful for native clients generally, so if those clients were
 * written in Java this would be a nice convenience. Web application clients are also a possiblity, although the
 * authorization code grant type is probably more common there, and requires no special customizations on the
 * authorization server. Callers add any additional form parameters they need to the {@link AccessTokenRequest} and
 * these will be passed onto the authorization endpoint on the server. The server then has to interpret those
 * parameters, together with any other information available (e.g. from a cookie), and decide if a user can be
 * authenticated and if the user has approved the grant of the access token. Only if those two conditions are met should
 * an access token be available through this provider.
 * 
 * @author Dave Syer
 */
public class ImplicitAccessTokenProvider extends OAuth2AccessTokenSupport implements AccessTokenProvider {

	public boolean supportsResource(OAuth2ProtectedResourceDetails resource) {
		return resource instanceof ImplicitResourceDetails && "implicit".equals(resource.getGrantType());
	}
	
	public boolean supportsRefresh() {
		return false;
	}
	
	public OAuth2AccessToken refreshAccessToken(OAuth2ProtectedResourceDetails resource,
			OAuth2RefreshToken refreshToken, AccessTokenRequest request) throws UserRedirectRequiredException {
		return null;
	}

	public OAuth2AccessToken obtainNewAccessToken(OAuth2ProtectedResourceDetails details, AccessTokenRequest request)
			throws UserRedirectRequiredException, AccessDeniedException {

		ImplicitResourceDetails resource = (ImplicitResourceDetails) details;

		if (request.isError()) {
			// there was an oauth error...
			throw getSerializationService().deserializeError(request.toSingleValueMap());
		}
		else {
			return retrieveToken(getParametersForTokenRequest(resource, request), resource);
		}

	}
	
	@Override
	protected ResponseExtractor<OAuth2AccessToken> getResponseExtractor() {
		return new ImplicitResponseExtractor();
	}

	private MultiValueMap<String, String> getParametersForTokenRequest(ImplicitResourceDetails resource,
			AccessTokenRequest request) {

		MultiValueMap<String, String> form = new LinkedMultiValueMap<String, String>();
		form.add("response_type", "token");

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

		for (String key : request.keySet()) {
			form.put(key, request.get(key));
		}

		if (request.getUserAuthorizationRedirectUri() == null && resource.getPreEstablishedRedirectUri() != null) {
			form.set("redirect_uri", resource.getPreEstablishedRedirectUri());
		}

		return form;

	}

	private final class ImplicitResponseExtractor implements ResponseExtractor<OAuth2AccessToken> {
		public OAuth2AccessToken extractData(ClientHttpResponse response) throws IOException {
			String fragment = response.getHeaders().getLocation().getFragment();
			Map<String, String> map = new HashMap<String, String>();
			Properties properties = StringUtils.splitArrayElementsIntoProperties(StringUtils.split(fragment, "&"), "=");
			for (Object key : properties.keySet()) {
				map.put(key.toString(), properties.get(key).toString());
			}
			return getSerializationService().deserializeAccessToken(map);
		}
	}

}
