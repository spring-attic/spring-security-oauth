package org.springframework.security.oauth2.consumer.webserver;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.*;
import org.springframework.security.oauth2.consumer.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Implementation of the web server client oauth2 flow.
 *
 * @author Ryan Heaton
 */
public class WebServerProfile extends OAuth2AccessTokenSupport implements OAuth2Profile {

  public OAuth2AccessToken obtainNewAccessToken(OAuth2ProtectedResourceDetails details) throws UserRedirectRequiredException, AccessDeniedException {
    WebServerProfileResourceDetails resource = (WebServerProfileResourceDetails) details;
    final OAuth2SecurityContext context = OAuth2SecurityContextHolder.getContext();
    String verificationCode = null;
    if (context != null) {
      verificationCode = context.getVerificationCode();
    }

    if (context != null && context.getErrorParameters() != null) {
      //there was an oauth error...
      throw getSerializationService().deserializeError(context.getErrorParameters());
    }
    else if (verificationCode == null) {
      //we don't have a verification code yet. So first get that.
      TreeMap<String, String> requestParameters = new TreeMap<String, String>();
      requestParameters.put("response_type", "code"); //oauth2 spec, section 3
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
      form.add("grant_type", "authorization_code");
      form.add("client_id", resource.getClientId());
      form.add("code", verificationCode);

      Object state = context == null ? null : context.getPreservedState();
      if (state == null) {
        //no state preserved? check for a pre-established redirect uri.
        state = resource.getPreEstablishedRedirectUri();
      }

      if (state == null) {
        //still no redirect uri? just try the one for the current context...
        state = context == null ? null : context.getUserAuthorizationRedirectUri();
      }

      form.add("redirect_uri", String.valueOf(state));

      return retrieveToken(form, resource);
    }
  }

  public boolean supportsResource(OAuth2ProtectedResourceDetails resource) {
    return resource instanceof WebServerProfileResourceDetails && "authorization_code".equals(resource.getGrantType());
  }
}
