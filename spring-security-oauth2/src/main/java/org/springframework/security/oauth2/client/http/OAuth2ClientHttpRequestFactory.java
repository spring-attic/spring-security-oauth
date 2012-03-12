package org.springframework.security.oauth2.client.http;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;

import org.springframework.http.HttpMethod;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.security.oauth2.client.UserRedirectRequiredException;
import org.springframework.security.oauth2.client.context.OAuth2ClientContext;
import org.springframework.security.oauth2.client.context.OAuth2ClientContextHolder;
import org.springframework.security.oauth2.client.resource.OAuth2AccessDeniedException;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.AccessTokenProvider;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.common.AuthenticationScheme;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.util.StringUtils;

/**
 * Request factory that extends all http requests with the OAuth 2 credentials for a specific protected resource.
 * 
 * @author Ryan Heaton
 * @author Roshan Dawrani
 */
public class OAuth2ClientHttpRequestFactory implements ClientHttpRequestFactory {

	private final ClientHttpRequestFactory delegate;

	private final OAuth2ProtectedResourceDetails resource;

	private final AccessTokenProvider accessTokenProvider;

	public OAuth2ClientHttpRequestFactory(ClientHttpRequestFactory delegate, AccessTokenProvider accessTokenProvider, OAuth2ProtectedResourceDetails resource) {
		this.delegate = delegate;
		this.accessTokenProvider = accessTokenProvider;
		this.resource = resource;

		if (delegate == null) {
			throw new IllegalArgumentException("A delegate must be supplied for an OAuth2ClientHttpRequestFactory.");
		}
		if (resource == null) {
			throw new IllegalArgumentException("A resource must be supplied for an OAuth2ClientHttpRequestFactory.");
		}
	}

	public ClientHttpRequest createRequest(URI uri, HttpMethod httpMethod) throws IOException {
		OAuth2ClientContext context = OAuth2ClientContextHolder.getContext();
		if (context == null) {
			throw new IllegalStateException(
					"No OAuth 2 security context has been established. Unable to access resource '"
							+ this.resource.getId() + "'.");
		}

		OAuth2AccessToken accessToken = context.getAccessToken(this.resource);

		if (accessToken == null || accessToken.isExpired()) {
			accessToken = acquireAccessToken(context);
		}

		String tokenType = accessToken.getTokenType();
		if (!StringUtils.hasText(tokenType)) {
			tokenType = OAuth2AccessToken.BEARER_TYPE; // we'll assume basic bearer token type if none is specified.
		}
		if (OAuth2AccessToken.BEARER_TYPE.equalsIgnoreCase(tokenType)
				|| OAuth2AccessToken.OAUTH2_TYPE.equalsIgnoreCase(tokenType)) {
			AuthenticationScheme bearerTokenMethod = resource.getAuthenticationScheme();
			if (AuthenticationScheme.query.equals(bearerTokenMethod)) {
				uri = appendQueryParameter(uri, accessToken);
			}

			ClientHttpRequest req = delegate.createRequest(uri, httpMethod);
			if (AuthenticationScheme.header.equals(bearerTokenMethod)) {
				req.getHeaders().add("Authorization",
						String.format("%s %s", OAuth2AccessToken.BEARER_TYPE, accessToken.getValue()));
			}
			return req;
		} else {
			throw new OAuth2AccessDeniedException("Unsupported access token type: " + tokenType);
		}
	}

	protected OAuth2AccessToken acquireAccessToken(OAuth2ClientContext oauth2Context) throws UserRedirectRequiredException {

		AccessTokenRequest accessTokenRequest = oauth2Context.getAccessTokenRequest();
		if (accessTokenRequest == null) {
			throw new AccessTokenRequiredException(
					"No OAuth 2 security context has been established. Unable to access resource '"
							+ this.resource.getId() + "'.", resource);
		}

		OAuth2AccessToken existingToken = oauth2Context.getAccessToken(resource);
		if (existingToken != null) {
			accessTokenRequest.setExistingToken(existingToken);
		}
		
		OAuth2AccessToken accessToken = null;
		accessToken = accessTokenProvider.obtainAccessToken(resource, accessTokenRequest);
		if (accessToken == null) {
			throw new IllegalStateException(
					"Access token manager returned a null access token, which is illegal according to the contract.");
		}
		oauth2Context.addAccessToken(resource, accessToken);
		return accessToken;
	}

	protected URI appendQueryParameter(URI uri, OAuth2AccessToken accessToken) {

		try {

			// TODO: there is some duplication with UriUtils here. Probably unavoidable as long as this
			// method signature uses URI not String.
			String query = uri.getQuery();
			String queryFragment = resource.getTokenName() + "=" + URLEncoder.encode(accessToken.getValue(), "UTF-8");
			if (query == null) {
				query = queryFragment;
			} else {
				query = query + "&" + queryFragment;
			}

			// first form the URI without query and fragment parts, so that it doesn't re-encode some query string chars
			// (SECOAUTH-90)
			URI update = new URI(uri.getScheme(), uri.getUserInfo(), uri.getHost(), uri.getPort(), uri.getPath(), null,
					null);
			// now add the encoded query string and the then fragment
			StringBuffer sb = new StringBuffer(update.toString());
			sb.append("?");
			sb.append(query);
			if (uri.getFragment() != null) {
				sb.append("#");
				sb.append(uri.getFragment());
			}

			return new URI(sb.toString());

		} catch (URISyntaxException e) {
			throw new IllegalArgumentException("Could not parse URI", e);
		} catch (UnsupportedEncodingException e) {
			throw new IllegalArgumentException("Could not encode URI", e);
		}

	}
}
