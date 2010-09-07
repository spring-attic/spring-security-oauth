package org.springframework.security.oauth2.consumer.webserver;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2Serialization;
import org.springframework.security.oauth2.consumer.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClientException;

import java.util.Iterator;
import java.util.List;
import java.util.TreeMap;

/**
 * Implementation of the web server client oauth2 flow.
 *
 * @author Ryan Heaton
 */
public class WebServerFlow extends AbstractOAuth2Flow {

  public OAuth2AccessToken obtainNewAccessToken(OAuth2ProtectedResourceDetails details) throws UserRedirectRequiredException, AccessDeniedException {
    WebServerFlowResourceDetails resource = (WebServerFlowResourceDetails) details;
    OAuth2SecurityContext context = OAuth2SecurityContextHolder.getContext();
    String verificationCode = null;
    if (context != null) {
      verificationCode = context.getVerificationCode();
    }

    if (verificationCode == null) {
      TreeMap<String, String> requestParameters = new TreeMap<String, String>();
      requestParameters.put("type", resource.getFlowType());
      requestParameters.put("client_id", resource.getClientId());
      String redirectUri = resource.getPreEstablishedRedirectUri();
      if (redirectUri == null) {
        if (context == null) {
          throw new IllegalStateException("No OAuth 2 security context has been established: unable to determine the redirect URI for the current context.");
        }
        redirectUri = context.getUserAuthorizationRedirectUri();
        if (redirectUri == null) {
          throw new IllegalStateException("No redirect URI has been established for the current OAuth 2 security context.");
        }
        requestParameters.put("redirect_uri", redirectUri);
      }
      else {
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

      if (resource.isRequireImmediateAuthorization()) {
        requestParameters.put("immediate", "true");
      }

      String stateKey = resource.getState();
      if (stateKey != null) {
        requestParameters.put("state", stateKey);
      }

      UserRedirectRequiredException redirectException = new UserRedirectRequiredException(resource.getUserAuthorizationUri(), requestParameters);
      if (redirectUri != null) {
        redirectException.setStateKey(resource.getState());
        redirectException.setStateToPreserve(redirectUri);
      }
      throw redirectException;
    }
    else {
      MultiValueMap<String, String> form = new LinkedMultiValueMap<String, String>();
      form.add("type", resource.getFlowType());
      form.add("client_id", resource.getClientId());
      if (resource.isSecretRequired()) {
        form.add("client_secret", resource.getClientSecret());
      }
      form.add("code", verificationCode);

      Object state = context.getPreservedState();
      if (state == null) {
        //no state preserved? check for a pre-established redirect uri.
        state = resource.getPreEstablishedRedirectUri();
      }

      if (state == null) {
        //still no redirect uri? just try the one for the current context...
        state = context == null ? null : context.getUserAuthorizationRedirectUri();
      }

      form.add("redirect_uri", String.valueOf(state));
      //todo: secret_type?
      form.add("format", "json");

      try {
        String response = getRestTemplate().postForObject(resource.getAccessTokenUri(), form, String.class);
        return getSerializationService().deserializeAccessToken(new OAuth2Serialization("application/json", response));
      }
      catch (HttpClientErrorException e) {
        throw new OAuth2AccessDeniedException("User denied access.", resource, e);
      }
      catch (RestClientException rce) {
        throw new OAuth2AccessDeniedException("Error requesting access token.", resource, rce);
      }
    }
  }

  public boolean supportsResource(OAuth2ProtectedResourceDetails resource) {
    return resource instanceof WebServerFlowResourceDetails && ("web_server".equals(resource.getFlowType()) || "web-server".equals(resource.getFlowType()));
  }
}
