package org.springframework.security.oauth2.provider.endpoint;

import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.View;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.util.HtmlUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Map;

/**
 * Controller for displaying the approval page for the authorization server.
 * 
 * @author Dave Syer
 */
@FrameworkEndpoint
@SessionAttributes("authorizationRequest")
public class WhitelabelApprovalEndpoint {

	@RequestMapping("/oauth/confirm_access")
	public ModelAndView getAccessConfirmation(Map<String, Object> model, HttpServletRequest request) throws Exception {
		final String approvalContent = createTemplate(model, request);
		if (request.getAttribute("_csrf") != null) {
			model.put("_csrf", request.getAttribute("_csrf"));
		}
		View approvalView = new View() {
			@Override
			public String getContentType() {
				return "text/html";
			}

			@Override
			public void render(Map<String, ?> model, HttpServletRequest request, HttpServletResponse response) throws Exception {
				response.setContentType(getContentType());
				response.getWriter().append(approvalContent);
			}
		};
		return new ModelAndView(approvalView, model);
	}

	protected String createTemplate(Map<String, Object> model, HttpServletRequest request) {
		AuthorizationRequest authorizationRequest = (AuthorizationRequest) model.get("authorizationRequest");
		String clientId = authorizationRequest.getClientId();

		StringBuilder builder = new StringBuilder();
		builder.append("<html><body><h1>OAuth Approval</h1>");
		builder.append("<p>Do you authorize \"").append(HtmlUtils.htmlEscape(clientId));
		builder.append("\" to access your protected resources?</p>");
		builder.append("<form id=\"confirmationForm\" name=\"confirmationForm\" action=\"");

		String requestPath = ServletUriComponentsBuilder.fromContextPath(request).build().getPath();
		if (requestPath == null) {
			requestPath = "";
		}

		builder.append(requestPath).append("/oauth/authorize\" method=\"post\">");
		builder.append("<input name=\"user_oauth_approval\" value=\"true\" type=\"hidden\"/>");

		String csrfTemplate = null;
		CsrfToken csrfToken = (CsrfToken) (model.containsKey("_csrf") ? model.get("_csrf") : request.getAttribute("_csrf"));
		if (csrfToken != null) {
			csrfTemplate = "<input type=\"hidden\" name=\"" + HtmlUtils.htmlEscape(csrfToken.getParameterName()) +
					"\" value=\"" + HtmlUtils.htmlEscape(csrfToken.getToken()) + "\" />";
		}
		if (csrfTemplate != null) {
			builder.append(csrfTemplate);
		}

		String authorizeInputTemplate = "<label><input name=\"authorize\" value=\"Authorize\" type=\"submit\"/></label></form>";

		if (model.containsKey("scopes") || request.getAttribute("scopes") != null) {
			builder.append(createScopes(model, request));
			builder.append(authorizeInputTemplate);
		} else {
			builder.append(authorizeInputTemplate);
			builder.append("<form id=\"denialForm\" name=\"denialForm\" action=\"");
			builder.append(requestPath).append("/oauth/authorize\" method=\"post\">");
			builder.append("<input name=\"user_oauth_approval\" value=\"false\" type=\"hidden\"/>");
			if (csrfTemplate != null) {
				builder.append(csrfTemplate);
			}
			builder.append("<label><input name=\"deny\" value=\"Deny\" type=\"submit\"/></label></form>");
		}

		builder.append("</body></html>");

		return builder.toString();
	}

	private CharSequence createScopes(Map<String, Object> model, HttpServletRequest request) {
		StringBuilder builder = new StringBuilder("<ul>");
		@SuppressWarnings("unchecked")
		Map<String, String> scopes = (Map<String, String>) (model.containsKey("scopes") ?
				model.get("scopes") : request.getAttribute("scopes"));
		for (String scope : scopes.keySet()) {
			String approved = "true".equals(scopes.get(scope)) ? " checked" : "";
			String denied = !"true".equals(scopes.get(scope)) ? " checked" : "";
			scope = HtmlUtils.htmlEscape(scope);

			builder.append("<li><div class=\"form-group\">");
			builder.append(scope).append(": <input type=\"radio\" name=\"");
			builder.append(scope).append("\" value=\"true\"").append(approved).append(">Approve</input> ");
			builder.append("<input type=\"radio\" name=\"").append(scope).append("\" value=\"false\"");
			builder.append(denied).append(">Deny</input></div></li>");
		}
		builder.append("</ul>");
		return builder.toString();
	}
}