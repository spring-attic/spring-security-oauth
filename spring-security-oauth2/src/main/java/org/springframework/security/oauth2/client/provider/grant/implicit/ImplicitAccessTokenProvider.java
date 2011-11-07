package org.springframework.security.oauth2.client.provider.grant.implicit;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.springframework.http.HttpMethod;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.client.UserRedirectRequiredException;
import org.springframework.security.oauth2.client.http.OAuth2AccessDeniedException;
import org.springframework.security.oauth2.client.provider.AccessTokenRequest;
import org.springframework.security.oauth2.client.provider.OAuth2AccessTokenProvider;
import org.springframework.security.oauth2.client.provider.OAuth2AccessTokenSupport;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RequestCallback;
import org.springframework.web.client.ResponseExtractor;
import org.springframework.web.client.RestClientException;
import org.springframework.web.util.UriTemplate;

/**
 * Provider for obtaining an oauth2 access token by using implicit grant.
 * 
 * @author Dave Syer
 */
public class ImplicitAccessTokenProvider extends OAuth2AccessTokenSupport implements OAuth2AccessTokenProvider {

	public boolean supportsResource(OAuth2ProtectedResourceDetails resource) {
		return resource instanceof ImplicitResourceDetails && "implicit".equals(resource.getGrantType());
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

	protected OAuth2AccessToken retrieveToken(MultiValueMap<String, String> form,
			OAuth2ProtectedResourceDetails resource) {

		try {
			String accessTokenUri = resource.getAccessTokenUri();

			if (logger.isDebugEnabled()) {
				logger.debug("Retrieving token from " + accessTokenUri);
			}

			getAuthenticationHandler().authenticateTokenRequest(
					resource,
					form,
					new SimpleClientHttpRequestFactory().createRequest(new UriTemplate(accessTokenUri).expand(),
							HttpMethod.GET));

			return getRestTemplate().execute(appendQueryParams(accessTokenUri, form, resource), HttpMethod.GET,
					new ImplicitTokenRequestCallback(resource), new ImplicitResponseExtractor(),
					form.toSingleValueMap());

		}
		catch (OAuth2Exception oe) {
			throw new OAuth2AccessDeniedException("Access token denied.", resource, oe);
		}
		catch (RestClientException e) {
			throw new OAuth2AccessDeniedException("Error requesting access token.", resource, e);
		}
		catch (IOException e) {
			throw new OAuth2AccessDeniedException("Unexpected error requesting access token.", resource, e);
		}

	}

	private String appendQueryParams(String accessTokenUri, MultiValueMap<String, String> form,
			OAuth2ProtectedResourceDetails resource) {
		StringBuilder builder = new StringBuilder(accessTokenUri);
		String separator = "?";
		if (accessTokenUri.contains("?")) {
			separator = "&";
		}
		for (String key : form.keySet()) {
			builder.append(separator);
			builder.append(key + "={" + key + "}");
			separator = "&";
		}
		return builder.toString();
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

	private class ImplicitTokenRequestCallback implements RequestCallback {

		private final OAuth2ProtectedResourceDetails resource;

		private ImplicitTokenRequestCallback(OAuth2ProtectedResourceDetails resource) {
			this.resource = resource;
		}

		public void doWithRequest(ClientHttpRequest request) throws IOException {
			getAuthenticationHandler().authenticateTokenRequest(this.resource,
					new LinkedMultiValueMap<String, String>(), request);
			request.getHeaders().setAccept(Arrays.asList(JSON_MEDIA_TYPE, FORM_MEDIA_TYPE));
		}

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
