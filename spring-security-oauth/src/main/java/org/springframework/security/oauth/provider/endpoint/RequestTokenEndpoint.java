/*
 * Copyright 2006-2014 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.springframework.security.oauth.provider.endpoint;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth.common.OAuthCodec;
import org.springframework.security.oauth.common.OAuthConstants;
import org.springframework.security.oauth.common.OAuthParameter;
import org.springframework.security.oauth.provider.ConsumerAuthentication;
import org.springframework.security.oauth.provider.InvalidOAuthParametersException;
import org.springframework.security.oauth.provider.token.OAuthProviderToken;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Handles requests for OAuth request tokens.
 *
 * @author Ryan Heaton
 * @author Andrew McCall
 * @author <a rel="author" href="http://autayeu.com/">Aliaksandr Autayeu</a>
 */
@FrameworkEndpoint
public class RequestTokenEndpoint extends AbstractEndpoint {

	@RequestMapping (value = OAuthConstants.DEFAULT_REQUEST_TOKEN_URL, method = {RequestMethod.GET, RequestMethod.POST})
	public void getRequestToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
		// request should be OAuth-authenticated
		if (!(SecurityContextHolder.getContext().getAuthentication() instanceof ConsumerAuthentication)) {
			throw new InvalidOAuthParametersException(messages.getMessage("RequestTokenEndpoint.missingCredentials", "Inadequate OAuth consumer credentials."));
		}
		ConsumerAuthentication authentication = (ConsumerAuthentication) SecurityContextHolder.getContext().getAuthentication();

		// validateAdditionalParameters
		if (isRequire10a()) {
			if (null == authentication.getOAuthParameters().getCallback()) {
				throw new InvalidOAuthParametersException(messages.getMessage("RequestTokenEndpoint.missingCallback", "Missing callback."));
			}
		}

		OAuthProviderToken authToken = createOAuthToken(authentication);
		if (!authToken.getConsumerKey().equals(authentication.getConsumerDetails().getConsumerKey())) {
			throw new IllegalStateException("The consumer key associated with the created auth token is not valid for the authenticated consumer.");
		}

		StringBuilder responseValue = new StringBuilder(OAuthParameter.oauth_token.toString())
				.append('=')
				.append(OAuthCodec.oauthEncode(authToken.getValue()))
				.append('&')
				.append(OAuthParameter.oauth_token_secret.toString())
				.append('=')
				.append(OAuthCodec.oauthEncode(authToken.getSecret()));
		if (null != authentication.getOAuthParameters().getCallback()) {
			responseValue.append('&')
					.append(OAuthParameter.oauth_callback_confirmed.toString())
					.append("=true");
		}
		response.setContentType(getResponseContentType());
		response.getWriter().print(responseValue.toString());
		response.flushBuffer();
	}

	/**
	 * Create the OAuth token for the specified consumer key.
	 *
	 * @param authentication The authentication request.
	 * @return The OAuth token.
	 */
	protected OAuthProviderToken createOAuthToken(ConsumerAuthentication authentication) {
		return getTokenServices().createUnauthorizedRequestToken(authentication.getConsumerDetails().getConsumerKey(),
																 authentication.getOAuthParameters().getCallback());
	}
}