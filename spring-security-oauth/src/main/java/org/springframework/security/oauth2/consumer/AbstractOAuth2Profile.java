package org.springframework.security.oauth2.consumer;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.security.oauth2.common.DefaultOAuth2SerializationService;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2SerializationService;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.common.exceptions.SerializationException;
import org.springframework.security.oauth2.consumer.auth.ClientAuthenticationHandler;
import org.springframework.security.oauth2.consumer.auth.DefaultClientAuthenticationHandler;
import org.springframework.util.Assert;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.*;

import java.io.IOException;
import java.util.Arrays;

/**
 * @author Ryan Heaton
 */
public abstract class AbstractOAuth2Profile implements OAuth2Profile, InitializingBean {

  public static final MediaType TOKEN_REQUEST_MEDIA_TYPE = new MediaType("application", "x-www-form-urlencoded");

  private final RestTemplate restTemplate;
  private OAuth2SerializationService serializationService = new DefaultOAuth2SerializationService();
  private ClientAuthenticationHandler authenticationHandler = new DefaultClientAuthenticationHandler();

  protected AbstractOAuth2Profile() {
    this.restTemplate = new RestTemplate();
    this.restTemplate.setErrorHandler(new AccessTokenErrorHandler());
  }

  public void afterPropertiesSet() throws Exception {
    Assert.notNull(restTemplate, "A RestTemplate is required.");
    Assert.notNull(serializationService, "OAuth2 serialization service is required.");
  }

  public RestTemplate getRestTemplate() {
    return restTemplate;
  }

  public OAuth2SerializationService getSerializationService() {
    return serializationService;
  }

  public void setSerializationService(OAuth2SerializationService serializationService) {
    this.serializationService = serializationService;
  }

  public ClientAuthenticationHandler getAuthenticationHandler() {
    return authenticationHandler;
  }

  public void setAuthenticationHandler(ClientAuthenticationHandler authenticationHandler) {
    this.authenticationHandler = authenticationHandler;
  }

  protected OAuth2AccessToken retrieveToken(MultiValueMap<String, String> form, OAuth2ProtectedResourceDetails resource) {
    try {
      String response = getRestTemplate().execute(resource.getAccessTokenUri(), HttpMethod.POST, new OAuth2AuthTokenCallback(form, resource),
                                                  new HttpMessageConverterExtractor<String>(String.class, getRestTemplate().getMessageConverters()));
      return getSerializationService().deserializeAccessToken(response);
    }
    catch (OAuth2Exception oe) {
      throw new OAuth2AccessDeniedException("Access token denied.", resource, oe);
    }
    catch (RestClientException rce) {
      throw new OAuth2AccessDeniedException("Error requesting access token.", resource, rce);
    }
  }

  /**
   * Request callback implementation that writes the given object to the request stream.
   */
  private class OAuth2AuthTokenCallback implements RequestCallback {

    private final MultiValueMap<String, String> form;
    private final OAuth2ProtectedResourceDetails resource;

    private OAuth2AuthTokenCallback(MultiValueMap<String, String> form, OAuth2ProtectedResourceDetails resource) {
      this.form = form;
      this.resource = resource;
    }

    public void doWithRequest(ClientHttpRequest request) throws IOException {
      getAuthenticationHandler().authenticateTokenRequest(this.resource, this.form, request);
      request.getHeaders().setAccept(Arrays.asList(new MediaType("application", "json")));
      for (HttpMessageConverter messageConverter : getRestTemplate().getMessageConverters()) {
        if (messageConverter.canWrite(MultiValueMap.class, TOKEN_REQUEST_MEDIA_TYPE)) {
          messageConverter.write(this.form, TOKEN_REQUEST_MEDIA_TYPE, request);
          return;
        }
      }
      throw new RestClientException("Couldn't write the request for an OAuth token: no converters found.");
    }
  }

  private class AccessTokenErrorHandler extends DefaultResponseErrorHandler {

    @Override
    public void handleError(ClientHttpResponse response) throws IOException {
      MediaType contentType = response.getHeaders().getContentType();
      if (contentType != null
        && "application".equalsIgnoreCase(contentType.getType())
        && "json".equalsIgnoreCase(contentType.getSubtype())
        && (response.getStatusCode().value() == 400 || response.getStatusCode().value() == 401)) {
        try {
          throw getSerializationService().deserializeJsonError(response.getBody());
        }
        catch (SerializationException e) {
          throw new OAuth2Exception("Error getting the access token, and unable to read the details of the error in the JSON response.", e);
        }
      }

      super.handleError(response);
    }

  }
}
