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

import java.io.UnsupportedEncodingException;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.oauth2.common.DefaultOAuth2SerializationService;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2SerializationService;
import org.springframework.security.oauth2.common.exceptions.UnsupportedGrantTypeException;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.stereotype.Controller;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * @author Dave Syer
 * 
 */
@Controller
public class TokenEndpoint implements InitializingBean {

	private String defaultGrantType = "authorization_code";
	private TokenGranter tokenGranter;
	private OAuth2SerializationService serializationService = new DefaultOAuth2SerializationService();
	private String credentialsCharset = "UTF-8";

	public void afterPropertiesSet() throws Exception {
		Assert.state(tokenGranter != null, "TokenGranter must be provided");
	}

	@RequestMapping(value = "/oauth/token")
	public ResponseEntity<String> getAccessToken(@RequestParam("grant_type") String grantType,
			@RequestParam Map<String, String> parameters, @RequestHeader HttpHeaders headers) {

		if (grantType == null) {
			grantType = defaultGrantType;
		}

		String[] clientValues = findClientSecret(headers, parameters);
		String clientId = clientValues[0];
		String clientSecret = clientValues[1];
		Set<String> scope = OAuth2Utils.parseScope(parameters.get("scope"));

		OAuth2AccessToken token = tokenGranter.grant(grantType, parameters, clientId, clientSecret, scope);
		if (token == null) {
			throw new UnsupportedGrantTypeException("Unsupported grant type: " + grantType);
		}

		return getResponse(token);

	}

	private ResponseEntity<String> getResponse(OAuth2AccessToken accessToken) {
		String serialization = serializationService.serialize(accessToken);
		HttpHeaders headers = new HttpHeaders();
		headers.set("Cache-Control", "no-store");
		headers.setContentType(MediaType.APPLICATION_JSON);
		return new ResponseEntity<String>(serialization, headers, HttpStatus.OK);
	}

	@Autowired
	public void setTokenGranter(TokenGranter tokenGranter) {
		this.tokenGranter = tokenGranter;
	}

	public void setDefaultGrantType(String defaultGrantType) {
		this.defaultGrantType = defaultGrantType;
	}

	/**
	 * Finds the client secret for the given client id and request. See the OAuth 2 spec, section 2.1.
	 * 
	 * @param request The request.
	 * @return The client secret, or null if none found in the request.
	 */
	protected String[] findClientSecret(HttpHeaders headers, Map<String, String> parameters) {
		String clientSecret = parameters.get("client_secret");
		String clientId = parameters.get("client_id");
		if (clientSecret == null) {
			List<String> auths = headers.get("Authorization");
			if (auths != null) {

				for (String header : auths) {

					if (header.startsWith("Basic ")) {

						String token;
						try {
							byte[] base64Token = header.substring(6).trim().getBytes("UTF-8");
							token = new String(Base64.decode(base64Token), getCredentialsCharset());
						} catch (UnsupportedEncodingException e) {
							throw new IllegalStateException("Unsupported encoding", e);
						}

						String username = "";
						String password = "";
						int delim = token.indexOf(":");

						if (delim != -1) {
							username = token.substring(0, delim);
							password = token.substring(delim + 1);
						}

						if (clientId != null && !username.equals(clientId)) {
							continue;
						}
						clientId = username;
						clientSecret = password;
						break;

					}
				}
			}
		}
		return new String[] { clientId, clientSecret };
	}

	public String getCredentialsCharset() {
		return credentialsCharset;
	}

	public void setCredentialsCharset(String credentialsCharset) {
		if (credentialsCharset == null) {
			throw new NullPointerException("credentials charset must not be null.");
		}

		this.credentialsCharset = credentialsCharset;
	}
}
