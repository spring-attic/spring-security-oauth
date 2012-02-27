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

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

/**
 * If authorization fails and the caller has asked for a specific content type response, this entry point can send one,
 * along with a standard 403 status. Add to the Spring Security configuration as an {@link AccessDeniedHandler} in
 * the usual way.
 * 
 * @author Dave Syer
 * 
 */
public class OAuth2AccessDeniedHandler extends AbstractOAuth2SecurityExceptionHandler implements AccessDeniedHandler {

	public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException authException)
			throws IOException, ServletException {
		doHandle(request, response, authException);
	}

}
