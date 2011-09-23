/*
 * Copyright 2002-2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.oauth2.provider.endpoint;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.DefaultOAuth2SerializationService;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2SerializationService;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.common.exceptions.UnsupportedGrantTypeException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2GrantManager;
import org.springframework.security.oauth2.provider.filter.DefaultOAuth2GrantManager;
import org.springframework.security.oauth2.provider.refresh.RefreshTokenDetails;
import org.springframework.security.oauth2.provider.token.OAuth2ProviderTokenServices;
import org.springframework.stereotype.Controller;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * @author Dave Syer
 * 
 */
@Controller
public class TokenEndpoint implements InitializingBean {

	private String defaultGrantType = "authorization_code";
	private OAuth2GrantManager grantManager = new DefaultOAuth2GrantManager();
	private AuthenticationManager authenticationManager;
	private OAuth2ProviderTokenServices tokenServices;
	private OAuth2SerializationService serializationService = new DefaultOAuth2SerializationService();

	public void afterPropertiesSet() throws Exception {
		Assert.state(tokenServices != null, "ProviderTokenServices must be provided");
	}

	@RequestMapping(value = "/oauth/token")
	public void getAccessToken(@RequestParam("grant_type") String grantType, HttpServletRequest request,
			HttpServletResponse response) throws IOException, ServletException {

		if (grantType == null) {
			grantType = defaultGrantType;
		}

		Authentication authentication = grantManager.setupAuthentication(grantType, request);
		if (authentication == null) {
			throw new UnsupportedGrantTypeException("Unsupported grant type: " + grantType);
		}

		authentication = authenticationManager.authenticate(authentication);
		onAuthenticationSuccess(request, response, authentication);

	}

	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {

		if (authentication instanceof OAuth2Authentication) {

			if (!authentication.isAuthenticated()) {
				throw new OAuth2Exception("Not authenticated.");
			}

			OAuth2Authentication oAuth2Auth = (OAuth2Authentication) authentication;
			Authentication clientAuth = oAuth2Auth.getClientAuthentication();
			OAuth2AccessToken accessToken;
			if (clientAuth.getDetails() instanceof RefreshTokenDetails) {
				accessToken = tokenServices.refreshAccessToken((RefreshTokenDetails) clientAuth.getDetails());
			} else {
				accessToken = tokenServices.createAccessToken(oAuth2Auth);
			}
			String serialization = serializationService.serialize(accessToken);
			response.setHeader("Cache-Control", "no-store");
			response.setContentType("application/json");
			response.getWriter().write(serialization);
			return;
		}

		throw new OAuth2Exception("Unsupported authentication for OAuth 2: " + authentication);

	}

	public void setAuthenticationManager(AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
	}

	@Autowired
	public void setTokenServices(OAuth2ProviderTokenServices tokenServices) {
		this.tokenServices = tokenServices;
	}

	public void setDefaultGrantType(String defaultGrantType) {
		this.defaultGrantType = defaultGrantType;
	}

}
