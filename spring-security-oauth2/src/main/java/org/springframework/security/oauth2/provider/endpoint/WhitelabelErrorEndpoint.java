package org.springframework.security.oauth2.provider.endpoint;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.util.HtmlUtils;

/**
 * Controller for displaying the error page for the authorization server.
 *
 * @author Dave Syer
 */
@FrameworkEndpoint
public class WhitelabelErrorEndpoint {

	private static final String ERROR = "<html><body><h1>OAuth Error</h1><p>${errorSummary}</p></body></html>";

	@RequestMapping("/oauth/error")
	public ModelAndView handleError(HttpServletRequest request) {
		Map<String, Object> model = new HashMap<String, Object>();
		Object error = request.getAttribute("error");
		// The error summary may contain malicious user input,
		// it needs to be escaped to prevent XSS
		String errorSummary;
		if (error instanceof OAuth2Exception) {
			OAuth2Exception oauthError = (OAuth2Exception) error;
			errorSummary = HtmlUtils.htmlEscape(oauthError.getSummary());
		}
		else {
			errorSummary = "Unknown error";
		}
		model.put("errorSummary", errorSummary);
		return new ModelAndView(new SpelView(ERROR), model);
	}
}
