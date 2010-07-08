package org.springframework.security.oauth.examples.sparklr.mvc;

import org.springframework.web.servlet.mvc.AbstractController;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.security.oauth.provider.token.OAuthProviderTokenServices;
import org.springframework.security.oauth.provider.token.OAuthProviderToken;
import org.springframework.security.oauth.provider.ConsumerDetailsService;
import org.springframework.security.oauth.provider.ConsumerDetails;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.TreeMap;

/**
 * Controller for retrieving the model for and displaying the confirmation page
 * for access to a protected resource.
 *
 * @author Ryan Heaton
 */
public class AccessConfirmationController extends AbstractController {

  private OAuthProviderTokenServices tokenServices;
  private ConsumerDetailsService consumerDetailsService;

  protected ModelAndView handleRequestInternal(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String token = request.getParameter("oauth_token");
    if (token == null) {
      throw new IllegalArgumentException("A request token to authorize must be provided.");
    }

    OAuthProviderToken providerToken = getTokenServices().getToken(token);
    ConsumerDetails consumer = getConsumerDetailsService().loadConsumerByConsumerKey(providerToken.getConsumerKey());

    String callback = request.getParameter("oauth_callback");
    TreeMap<String, Object> model = new TreeMap<String, Object>();
    model.put("oauth_token", token);
    if (callback != null) {
      model.put("oauth_callback", callback);
    }
    model.put("consumer", consumer);
    return new ModelAndView("access_confirmation", model);
  }

  public OAuthProviderTokenServices getTokenServices() {
    return tokenServices;
  }

  public void setTokenServices(OAuthProviderTokenServices tokenServices) {
    this.tokenServices = tokenServices;
  }

  public ConsumerDetailsService getConsumerDetailsService() {
    return consumerDetailsService;
  }

  public void setConsumerDetailsService(ConsumerDetailsService consumerDetailsService) {
    this.consumerDetailsService = consumerDetailsService;
  }
}
