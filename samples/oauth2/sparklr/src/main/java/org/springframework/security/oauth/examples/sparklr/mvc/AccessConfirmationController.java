package org.springframework.security.oauth.examples.sparklr.mvc;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.provider.ClientToken;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.code.ClientTokenCache;
import org.springframework.security.oauth2.provider.code.DefaultClientTokenCache;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.TreeMap;

/**
 * Controller for retrieving the model for and displaying the confirmation page
 * for access to a protected resource.
 *
 * @author Ryan Heaton
 */
@Controller
public class AccessConfirmationController {

  private ClientTokenCache authenticationCache = new DefaultClientTokenCache();
  private ClientDetailsService clientDetailsService;

  @RequestMapping("/oauth/confirm_access")
  public ModelAndView getAccessConfirmation(HttpServletRequest request, HttpServletResponse response) throws Exception {
    ClientToken clientAuth = getAuthenticationCache().getToken(request, response);
    if (clientAuth == null) {
      throw new IllegalStateException("No client authentication request to authorize.");
    }

    ClientDetails client = getClientDetailsService().loadClientByClientId(clientAuth.getClientId());
    TreeMap<String, Object> model = new TreeMap<String, Object>();
    model.put("auth_request", clientAuth);
    model.put("client", client);
    return new ModelAndView("access_confirmation", model);
  }

  public ClientTokenCache getAuthenticationCache() {
    return authenticationCache;
  }

  @Autowired
  public void setAuthenticationCache(ClientTokenCache authenticationCache) {
    this.authenticationCache = authenticationCache;
  }

  public ClientDetailsService getClientDetailsService() {
    return clientDetailsService;
  }

  @Autowired
  public void setClientDetailsService(ClientDetailsService clientDetailsService) {
    this.clientDetailsService = clientDetailsService;
  }
}
