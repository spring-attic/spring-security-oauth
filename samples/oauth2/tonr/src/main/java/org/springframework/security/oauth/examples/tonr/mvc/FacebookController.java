package org.springframework.security.oauth.examples.tonr.mvc;

import java.util.ArrayList;

import org.codehaus.jackson.JsonNode;
import org.codehaus.jackson.node.ArrayNode;
import org.codehaus.jackson.node.ObjectNode;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.client.RestOperations;

/**
 * @author Ryan Heaton
 * @author Dave Syer
 */
@Controller
public class FacebookController {

	private RestOperations facebookRestTemplate;

	@RequestMapping("/facebook/info")
	public String photos(Model model) throws Exception {
		ObjectNode result = facebookRestTemplate
				.getForObject("https://graph.facebook.com/me/friends", ObjectNode.class);
		ArrayNode data = (ArrayNode) result.get("data");
		ArrayList<String> friends = new ArrayList<String>();
		for (JsonNode dataNode : data) {
			friends.add(dataNode.get("name").getTextValue());
		}
		model.addAttribute("friends", friends);
		return "facebook";
	}

	public void setFacebookRestTemplate(OAuth2RestTemplate facebookRestTemplate) {
		this.facebookRestTemplate = facebookRestTemplate;
	}

}
