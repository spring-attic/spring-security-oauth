/*
 * Copyright 2008 Web Cohesion
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.oauth.provider;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth.common.signature.UnsupportedSignatureMethodException;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

/**
 * Entry point for OAuth authentication requests.
 *
 * @author Ryan Heaton
 */
public class OAuthProcessingFilterEntryPoint implements AuthenticationEntryPoint {

  private String realmName;

  public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
	  if (authException instanceof InvalidOAuthParametersException) {
		  response.sendError(400, authException.getMessage());
	  }
	  else if (authException.getCause() instanceof UnsupportedSignatureMethodException) {
		  response.sendError(400, authException.getMessage());
	  }
	  else {
		  StringBuilder headerValue = new StringBuilder("OAuth");
		  if (realmName != null) {
			  headerValue.append(" realm=\"").append(realmName).append('"');
		  }
		  response.addHeader("WWW-Authenticate", headerValue.toString());
		  response.sendError(HttpServletResponse.SC_UNAUTHORIZED, authException.getMessage());
	  }
  }

  public String getRealmName() {
    return realmName;
  }

  public void setRealmName(String realmName) {
    this.realmName = realmName;
  }

}