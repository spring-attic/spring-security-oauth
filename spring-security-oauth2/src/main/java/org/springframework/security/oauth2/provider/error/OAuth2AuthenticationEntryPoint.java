/*
 * Copyright 2006-2011 the original author or authors.
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
package org.springframework.security.oauth2.provider.error;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.util.StringUtils;

/**
 * If authentication fails and the caller has asked for a specific content type response, this entry point can send one,
 * along with a standard 401 status. Add to the Spring Security configuration as an {@link AuthenticationEntryPoint} in
 * the usual way.
 * 
 * @author Dave Syer
 * 
 */
public class OAuth2AuthenticationEntryPoint extends AbstractOAuth2SecurityExceptionHandler implements
		AuthenticationEntryPoint {

	private String typeName = OAuth2AccessToken.BEARER_TYPE;

	private String realmName = "oauth";

	public void setRealmName(String realmName) {
		this.realmName = realmName;
	}

	public void setTypeName(String typeName) {
		this.typeName = typeName;
	}

	public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException)
			throws IOException, ServletException {
		doHandle(request, response, authException);
	}

	@Override
	protected ResponseEntity<OAuth2Exception> enhanceResponse(ResponseEntity<OAuth2Exception> response, Exception exception) {
		HttpHeaders headers = response.getHeaders();
		String existing = null;
		if (headers.containsKey("WWW-Authenticate")) {
			existing = extractTypePrefix(headers.getFirst("WWW-Authenticate"));
		}
		StringBuilder builder = new StringBuilder();
		builder.append(typeName+" ");
		builder.append("realm=\"" + realmName + "\"");
		if (existing!=null) {
			builder.append(", "+existing);
		}
		HttpHeaders update = new HttpHeaders();
		update.putAll(response.getHeaders());
		update.set("WWW-Authenticate", builder.toString());
		return new ResponseEntity<OAuth2Exception>(response.getBody(), update, response.getStatusCode());
	}

	private String extractTypePrefix(String header) {
		String existing = header;
		String[] tokens = existing.split(" +");
		if (tokens.length > 1 && !tokens[0].endsWith(",")) {
			existing = StringUtils.arrayToDelimitedString(tokens, " ").substring(existing.indexOf(" ") + 1);
		}
		return existing;
	}

}
