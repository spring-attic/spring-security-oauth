package org.springframework.security.oauth.examples.tonr.mvc;

import org.codehaus.jackson.JsonNode;
import org.codehaus.jackson.node.ArrayNode;
import org.codehaus.jackson.node.ObjectNode;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.consumer.*;
import org.springframework.security.oauth2.consumer.token.OAuth2ClientTokenServices;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.AbstractController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.ArrayList;

/**
 * @author Ryan Heaton
 */
public class FacebookController extends AbstractController {

  private OAuth2RestTemplate facebookRestTemplate;
  private OAuth2ClientTokenServices tokenServices;

  protected ModelAndView handleRequestInternal(HttpServletRequest request, HttpServletResponse response) throws Exception {
    try {
      ObjectNode result = getFacebookRestTemplate().getForObject("https://graph.facebook.com/me/friends", ObjectNode.class);
      ArrayNode data = (ArrayNode) result.get("data");
      ArrayList<String> friends = new ArrayList<String>();
      for (JsonNode dataNode : data) {
        friends.add(dataNode.get("name").getTextValue());
      }
      return new ModelAndView("facebook", "friends", friends);
    }
    catch (HttpClientErrorException clientError) {
      if (clientError.getStatusCode().value() == 400) {
        //there are multiple reasons we could get a 400, but we're going to assume the token was revoked.
        //we've got a bad token, probably because it's expired or revoked.
        OAuth2ProtectedResourceDetails resource = getFacebookRestTemplate().getResource();
        OAuth2SecurityContext context = OAuth2SecurityContextHolder.getContext();
        if (context != null) {
          // this one is kind of a hack for this application
          // the problem is that the facebook friends page doesn't remove the 'code=' request parameter.
          ((OAuth2SecurityContextImpl) context).setVerificationCode(null);
        }
        //clear any stored access tokens...
        getTokenServices().removeToken(SecurityContextHolder.getContext().getAuthentication(), resource);
        //go get a new access token...
        throw new OAuth2AccessTokenRequiredException(resource);
      }
      else {
        throw clientError;
      }
    }
  }

  public OAuth2RestTemplate getFacebookRestTemplate() {
    return facebookRestTemplate;
  }

  public void setFacebookRestTemplate(OAuth2RestTemplate facebookRestTemplate) {
    this.facebookRestTemplate = facebookRestTemplate;
  }

  public OAuth2ClientTokenServices getTokenServices() {
    return tokenServices;
  }

  public void setTokenServices(OAuth2ClientTokenServices tokenServices) {
    this.tokenServices = tokenServices;
  }
}
