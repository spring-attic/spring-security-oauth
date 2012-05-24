package org.springframework.security.oauth.examples.sparklr.mvc;

import java.util.Map;
import java.util.TreeMap;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.servlet.ModelAndView;

/**
 * Controller for retrieving the model for and displaying the confirmation page for access to a protected resource.
 * 
 * @author Ryan Heaton
 */
@Controller
@SessionAttributes(types = AuthorizationRequest.class)
public class AccessConfirmationController {

	private ClientDetailsService clientDetailsService;

	@RequestMapping("/oauth/confirm_access")
	public ModelAndView getAccessConfirmation(@ModelAttribute AuthorizationRequest clientAuth) throws Exception {
		ClientDetails client = clientDetailsService.loadClientByClientId(clientAuth.getClientId());
		TreeMap<String, Object> model = new TreeMap<String, Object>();
		model.put("auth_request", clientAuth);
		model.put("client", client);
		return new ModelAndView("access_confirmation", model);
	}

	@RequestMapping("/oauth/error")
	public String handleError(Map<String,Object> model) throws Exception {
		// We can add more stuff to the model here for JSP rendering.  If the client was a machine then
		// the JSON will already have been rendered.
		model.put("message", "There was a problem with the OAuth2 protocol");
		return "oauth_error";
	}

	@Autowired
	public void setClientDetailsService(ClientDetailsService clientDetailsService) {
		this.clientDetailsService = clientDetailsService;
	}
}
