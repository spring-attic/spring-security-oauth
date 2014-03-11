package org.springframework.security.oauth2.client.token.grant.implicit;

import java.io.IOException;
import java.net.URI;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import org.springframework.http.HttpHeaders;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.client.resource.OAuth2AccessDeniedException;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.resource.UserRedirectRequiredException;
import org.springframework.security.oauth2.client.token.AccessTokenProvider;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.DefaultAccessTokenRequest;
import org.springframework.security.oauth2.client.token.OAuth2AccessTokenSupport;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.ResponseExtractor;

/**
 * Provider for obtaining an oauth2 access token by using implicit grant. Normally the implicit grant is used by script
 * clients in a browser or device, but it can also be useful for native clients generally, so if those clients were
 * written in Java this would be a nice convenience. Web application clients are also a possiblity, although the
 * authorization code grant type is probably more common there, and requires no special customizations on the
 * authorization server. Callers add any additional form parameters they need to the {@link DefaultAccessTokenRequest}
 * and these will be passed onto the authorization endpoint on the server. The server then has to interpret those
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

	public boolean supportsRefresh(OAuth2ProtectedResourceDetails resource) {
		return false;
	}

	public OAuth2AccessToken refreshAccessToken(OAuth2ProtectedResourceDetails resource,
			OAuth2RefreshToken refreshToken, AccessTokenRequest request) throws UserRedirectRequiredException {
		return null;
	}

	public OAuth2AccessToken obtainAccessToken(OAuth2ProtectedResourceDetails details, AccessTokenRequest request)
			throws UserRedirectRequiredException, AccessDeniedException, OAuth2AccessDeniedException {

		ImplicitResourceDetails resource = (ImplicitResourceDetails) details;
		try {
			// We can assume here that the request contains all the parameters needed for authentication etc.
			OAuth2AccessToken token = retrieveToken(request,
					resource, getParametersForTokenRequest(resource, request), getHeadersForTokenRequest(request));
			if (token==null) {
				// Probably an authenticated request, but approval is required.  TODO: prompt somehow?
				throw new UserRedirectRequiredException(resource.getUserAuthorizationUri(), request.toSingleValueMap());				
			}
			return token;
		}
		catch (UserRedirectRequiredException e) {
			// ... but if it doesn't then capture the request parameters for the redirect
			throw new UserRedirectRequiredException(e.getRedirectUri(), request.toSingleValueMap());
		}

	}

	@Override
	protected ResponseExtractor<OAuth2AccessToken> getResponseExtractor() {
		return new ImplicitResponseExtractor();
	}

	private HttpHeaders getHeadersForTokenRequest(AccessTokenRequest request) {
		HttpHeaders headers = new HttpHeaders();
		headers.putAll(request.getHeaders());
		if (request.getCookie() != null) {
			headers.set("Cookie", request.getCookie());
		}
		return headers;
	}

	private MultiValueMap<String, String> getParametersForTokenRequest(ImplicitResourceDetails resource,
			AccessTokenRequest request) {

		MultiValueMap<String, String> form = new LinkedMultiValueMap<String, String>();
		form.set("response_type", "token");
		form.set("client_id", resource.getClientId());
		
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

			form.set("scope", builder.toString());
		}

		for (String key : request.keySet()) {
			form.put(key, request.get(key));
		}

		String redirectUri = resource.getRedirectUri(request);
		if (redirectUri == null) {
			throw new IllegalStateException("No redirect URI available in request");
		}
		form.set("redirect_uri", redirectUri);

		return form;

	}

	private final class ImplicitResponseExtractor implements ResponseExtractor<OAuth2AccessToken> {
		public OAuth2AccessToken extractData(ClientHttpResponse response) throws IOException {
			// TODO: this should actually be a 401 if the request asked for JSON
			URI location = response.getHeaders().getLocation();
			if (location == null) {
				return null;
			}
			String fragment = location.getFragment();
			OAuth2AccessToken accessToken = DefaultOAuth2AccessToken.valueOf(OAuth2Utils.extractMap(fragment));
			if (accessToken.getValue() == null) {
				throw new UserRedirectRequiredException(location.toString(), Collections.<String, String> emptyMap());
			}

			return accessToken;
		}
	}

}
