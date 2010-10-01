package org.springframework.security.oauth.examples.sparklr.mvc;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.security.oauth2.provider.ClientAuthenticationToken;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.verification.ClientAuthenticationCache;
import org.springframework.security.oauth2.provider.verification.DefaultClientAuthenticationCache;
import org.springframework.util.Assert;
import org.springframework.web.servlet.mvc.AbstractController;
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
public class AccessConfirmationController extends AbstractController {

  private ClientAuthenticationCache authenticationCache = new DefaultClientAuthenticationCache();
  private ClientDetailsService clientDetailsService;

  @Override
  protected void initApplicationContext(ApplicationContext context) {
    super.initApplicationContext(context);
    Assert.notNull(clientDetailsService, "A client details service must be supplied.");
  }

  protected ModelAndView handleRequestInternal(HttpServletRequest request, HttpServletResponse response) throws Exception {
    ClientAuthenticationToken clientAuth = getAuthenticationCache().getAuthentication(request, response);
    if (clientAuth == null) {
      throw new IllegalStateException("No client authentication request to authorize.");
    }

    ClientDetails client = getClientDetailsService().loadClientByClientId(clientAuth.getClientId());
    TreeMap<String, Object> model = new TreeMap<String, Object>();
    model.put("auth_request", clientAuth);
    model.put("client", client);
    return new ModelAndView("access_confirmation", model);
  }

  public ClientAuthenticationCache getAuthenticationCache() {
    return authenticationCache;
  }

  @Autowired
  public void setAuthenticationCache(ClientAuthenticationCache authenticationCache) {
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
