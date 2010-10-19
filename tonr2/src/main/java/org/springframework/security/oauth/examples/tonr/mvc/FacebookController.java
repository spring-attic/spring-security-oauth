package org.springframework.security.oauth.examples.tonr.mvc;

import org.codehaus.jackson.JsonNode;
import org.codehaus.jackson.node.ArrayNode;
import org.codehaus.jackson.node.ObjectNode;
import org.springframework.security.oauth2.consumer.OAuth2RestTemplate;
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

  protected ModelAndView handleRequestInternal(HttpServletRequest request, HttpServletResponse response) throws Exception {
    ObjectNode result = getFacebookRestTemplate().getForObject("https://graph.facebook.com/me/friends", ObjectNode.class);
    ArrayNode data = (ArrayNode) result.get("data");
    ArrayList<String> friends = new ArrayList<String>();
    for (JsonNode dataNode : data) {
      friends.add(dataNode.get("name").getTextValue());
    }
    return new ModelAndView("facebook", "friends", friends);
  }

  public OAuth2RestTemplate getFacebookRestTemplate() {
    return facebookRestTemplate;
  }

  public void setFacebookRestTemplate(OAuth2RestTemplate facebookRestTemplate) {
    this.facebookRestTemplate = facebookRestTemplate;
  }
}
