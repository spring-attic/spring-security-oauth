package org.springframework.security.oauth2.provider.endpoint;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

/**
 * Controller for displaying the error page for the authorization server.
 * 
 * @author Dave Syer
 */
@FrameworkEndpoint
public class WhitelabelErrorEndpoint {

	@RequestMapping("/oauth/error")
	public ModelAndView handleError(HttpServletRequest request) {
		Map<String, Object> model = new HashMap<String, Object>();
		model.put("error", request.getAttribute("error"));
		return new ModelAndView(new SpelView(ERROR), model);
	}

	private static String ERROR = "<html><body><h1>OAuth Error</h1><p>${error.summary}</p></body></html>";

}
