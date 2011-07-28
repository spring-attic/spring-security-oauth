package org.springframework.security.oauth.examples.sparklr.mvc;

import java.util.TreeMap;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.oauth.provider.ConsumerDetails;
import org.springframework.security.oauth.provider.ConsumerDetailsService;
import org.springframework.security.oauth.provider.token.OAuthProviderToken;
import org.springframework.security.oauth.provider.token.OAuthProviderTokenServices;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

/**
 * Controller for retrieving the model for and displaying the confirmation page for access to a protected resource.
 * 
 * @author Ryan Heaton
 * @author Dave Syer
 */
@Controller
public class AccessConfirmationController {

	private OAuthProviderTokenServices tokenServices;
	private ConsumerDetailsService consumerDetailsService;

	@RequestMapping("/oauth/confirm_access")
	public ModelAndView getAccessConfirmation(HttpServletRequest request, HttpServletResponse response)
			throws Exception {
		String token = request.getParameter("oauth_token");
		if (token == null) {
			throw new IllegalArgumentException("A request token to authorize must be provided.");
		}

		OAuthProviderToken providerToken = tokenServices.getToken(token);
		ConsumerDetails consumer = consumerDetailsService
				.loadConsumerByConsumerKey(providerToken.getConsumerKey());

		String callback = request.getParameter("oauth_callback");
		TreeMap<String, Object> model = new TreeMap<String, Object>();
		model.put("oauth_token", token);
		if (callback != null) {
			model.put("oauth_callback", callback);
		}
		model.put("consumer", consumer);
		return new ModelAndView("access_confirmation", model);
	}

	public void setTokenServices(OAuthProviderTokenServices tokenServices) {
		this.tokenServices = tokenServices;
	}

	public void setConsumerDetailsService(ConsumerDetailsService consumerDetailsService) {
		this.consumerDetailsService = consumerDetailsService;
	}
}
