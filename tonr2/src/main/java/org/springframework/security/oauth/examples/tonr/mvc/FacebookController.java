package org.springframework.security.oauth.examples.tonr.mvc;

import java.util.ArrayList;

import org.codehaus.jackson.JsonNode;
import org.codehaus.jackson.node.ArrayNode;
import org.codehaus.jackson.node.ObjectNode;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.consumer.OAuth2AccessTokenRequiredException;
import org.springframework.security.oauth2.consumer.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.consumer.OAuth2RestTemplate;
import org.springframework.security.oauth2.consumer.OAuth2SecurityContext;
import org.springframework.security.oauth2.consumer.OAuth2SecurityContextHolder;
import org.springframework.security.oauth2.consumer.OAuth2SecurityContextImpl;
import org.springframework.security.oauth2.consumer.token.OAuth2ClientTokenServices;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.client.HttpClientErrorException;

/**
 * @author Ryan Heaton
 * @author Dave Syer
 */
@Controller
public class FacebookController {

	private OAuth2RestTemplate facebookRestTemplate;
	private OAuth2ClientTokenServices tokenServices;

	@RequestMapping("/info.jsp")
	public String photos(Model model) throws Exception {
		try {
			ObjectNode result = facebookRestTemplate.getForObject("https://graph.facebook.com/me/friends",
					ObjectNode.class);
			ArrayNode data = (ArrayNode) result.get("data");
			ArrayList<String> friends = new ArrayList<String>();
			for (JsonNode dataNode : data) {
				friends.add(dataNode.get("name").getTextValue());
			}
			model.addAttribute("friends", friends);
			return "facebook";
		} catch (HttpClientErrorException clientError) {
			if (clientError.getStatusCode().value() == 400) {
				// there are multiple reasons we could get a 400, but we're going to assume the token was revoked.
				// we've got a bad token, probably because it's expired or revoked.
				OAuth2ProtectedResourceDetails resource = facebookRestTemplate.getResource();
				OAuth2SecurityContext context = OAuth2SecurityContextHolder.getContext();
				if (context != null) {
					// this one is kind of a hack for this application
					// the problem is that the facebook friends page doesn't remove the 'code=' request parameter.
					((OAuth2SecurityContextImpl) context).setVerificationCode(null);
				}
				// clear any stored access tokens...
				tokenServices.removeToken(SecurityContextHolder.getContext().getAuthentication(), resource);
				// go get a new access token...
				throw new OAuth2AccessTokenRequiredException(resource);
			} else {
				throw clientError;
			}
		}
	}

	public void setFacebookRestTemplate(OAuth2RestTemplate facebookRestTemplate) {
		this.facebookRestTemplate = facebookRestTemplate;
	}

	public void setTokenServices(OAuth2ClientTokenServices tokenServices) {
		this.tokenServices = tokenServices;
	}
}
