package org.springframework.security.oauth2.provider.endpoint;

import java.util.Map;
import java.util.regex.Pattern;

import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.util.UriUtils;

/**
 * Controller for displaying authorization code for the authorization server.
 * 
 * @author Miyamoto Daisuke
 */
@FrameworkEndpoint
public class WhitelabelOutOfBandRedirectEndpoint {
	
	private static final Pattern VALID_PATTERN = Pattern.compile("^[ 0-9A-Za-z%_]*$");

	@RequestMapping("/oauth/oob")
	public ModelAndView getAuthorizationCodeDisplay(Map<String, Object> model,
			@RequestParam(value = "code", required= false) String code,
			@RequestParam(value = "error", required= false) String error,
			@RequestParam(value = "error_description", required= false) String desc,
			@RequestParam(value = "state", required= false) String state) throws Exception {
		
		String template;
		if (StringUtils.isEmpty(error)) {
			template = SUCCESS_TEMPLATE
					.replace("%code%", sanitize(code))
					.replace("%codeq%", UriUtils.encodeQueryParam(sanitize(code), "UTF-8"));
		} else {
			template = ERROR_TEMPLATE
					.replace("%error%", sanitize(error))
					.replace("%errorq%", UriUtils.encodeQueryParam(sanitize(error), "UTF-8"))
					.replace("%desc%", sanitize(desc))
					.replace("%descq%", StringUtils.isEmpty(desc) ? "" : "&error_description="
							+ UriUtils.encodeQueryParam(sanitize(desc), "UTF-8"));
		}
		template = template.replace("%stateq%", StringUtils.isEmpty(state) ? "" : "&state="
				+ UriUtils.encodeQueryParam(sanitize(state), "UTF-8"));
		return new ModelAndView(new SpelView(template), model);
	}

	protected String sanitize(String input) {
		if (VALID_PATTERN.matcher(input).matches()) {
			return input;
		}
		return "invalid";
	}

	private static String SUCCESS_TEMPLATE = "<html><head>"
			+ "<title>Success code=%codeq%%stateq%</title>"
			+ "</head><body><h1>OAuth Authorization Code</h1>"
			+ "<p>Copy and paste this code to your mobile phones or command-line utilities.</p>"
			+ "<p>Code: %code%</p>"
			+ "</body></html>";

	private static String ERROR_TEMPLATE = "<html><head>"
			+ "<title>Denied error=%errorq%%descq%%stateq%</title>"
			+ "</head><body><h1>OAuth Authorization Code</h1>"
			+ "<p>Error: %error%</p>"
			+ "<p>Description: %desc%</p>"
			+ "</body></html>";
}
