package org.springframework.security.oauth2.consumer;

import org.springframework.http.HttpMethod;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.util.Map;

/**
 * Request factory that extends all http requests with the OAuth 2 credentials for a specific protected resource.
 *
 * @author Ryan Heaton
 */
public class OAuth2ClientHttpRequestFactory implements ClientHttpRequestFactory {

  private final ClientHttpRequestFactory delegate;
  private final OAuth2ProtectedResourceDetails resource;

  public OAuth2ClientHttpRequestFactory(ClientHttpRequestFactory delegate, OAuth2ProtectedResourceDetails resource) {
    this.delegate = delegate;
    this.resource = resource;

    if (delegate == null) {
      throw new IllegalArgumentException("A delegate must be supplied for an OAuth2ClientHttpRequestFactory.");
    }
    if (resource == null) {
      throw new IllegalArgumentException("A resource must be supplied for an OAuth2ClientHttpRequestFactory.");
    }
  }

  public ClientHttpRequest createRequest(URI uri, HttpMethod httpMethod) throws IOException {
    OAuth2SecurityContext context = OAuth2SecurityContextHolder.getContext();
    if (context == null) {
      throw new IllegalStateException("No OAuth 2 security context has been established. Unable to access resource '" + this.resource.getId() + "'.");
    }

    Map<String,OAuth2AccessToken> accessTokens = context.getAccessTokens();
    OAuth2AccessToken accessToken = accessTokens == null ? null : accessTokens.get(this.resource.getId());
    if (accessToken == null) {
      throw new OAuth2AccessTokenRequiredException("No OAuth 2 security context has been established. Unable to access resource '" + this.resource.getId() + "'.", resource);
    }

    String tokenType = accessToken.getTokenType();
    if (tokenType == null || "".equals(tokenType)) {
      tokenType = "OAuth2"; //we'll assume basic bearer token type if none is specified.
    }
    if ("OAuth2".equalsIgnoreCase(tokenType)) {
      OAuth2ProtectedResourceDetails.BearerTokenMethod bearerTokenMethod = resource.getBearerTokenMethod();
      if (OAuth2ProtectedResourceDetails.BearerTokenMethod.query.equals(bearerTokenMethod)) {
        uri = appendQueryParameter(uri, accessToken);
      }

      ClientHttpRequest req = delegate.createRequest(uri, httpMethod);
      if (OAuth2ProtectedResourceDetails.BearerTokenMethod.header.equals(bearerTokenMethod)) {
        req.getHeaders().add("Authorization", String.format("OAuth %s", accessToken.getValue()));
      }
      return req;
    }
    else {
      throw new InvalidTokenException("Unsupported access token type: " + tokenType);
    }
  }

  protected URI appendQueryParameter(URI uri, OAuth2AccessToken accessToken) {
    try {
      String query = uri.getQuery();
      String queryFragment = ((resource.getBearerTokenName() == null) ? "oauth_token" : resource.getBearerTokenName()) + "=" + URLEncoder.encode(accessToken.getValue(), "UTF-8");
      if (query == null) {
        query = queryFragment;
      }
      else {
        query = query + "&" + queryFragment;
      }
      
      uri = new URI(uri.getScheme(), uri.getUserInfo(), uri.getHost(), uri.getPort(), uri.getPath(), query, uri.getFragment());
      return uri;
    }
    catch (RuntimeException e) {
      throw e;
    }
    catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}
