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
import java.util.LinkedHashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.util.StringUtils;

/**
 * If authorization fails and the caller has asked for a specific content type response, this entry point can send one,
 * along with a standard 401 status. Add to the Spring Security configuration as an {@link AuthenticationEntryPoint} in
 * the usual way.
 * 
 * @author Dave Syer
 * 
 */
public class MediaTypeAwareAccessDeniedHandler implements AccessDeniedHandler {

	private Map<MediaType, String> responses = new LinkedHashMap<MediaType, String>();

	{
		responses.put(MediaType.APPLICATION_JSON, "{\"error\":\"%s\"}");
		responses.put(MediaType.APPLICATION_XML, "<error>%s</error>");
	}

	/**
	 * A mapping from supported media type to a String to use to format the response. The default response generation
	 * implementation assumes that string responses contain a {@link String#format(String, Object...) format
	 * placeholder} for an error message. Defaults are provided for JSON and XML with very basic formats. The default
	 * format if no match is found is empty, so to provide an explicit default use and ordered map woth
	 * {@link MediaType#ALL} as the last entry in the map.
	 * 
	 * @param responses the responses to set
	 */
	public void setResponses(Map<MediaType, String> responses) {
		this.responses = new LinkedHashMap<MediaType, String>(responses);
	}

	public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException authException)
			throws IOException, ServletException {
		String accept = request.getHeader("Accept");
		MediaType mediaType = selectMediaType(accept);
		if (mediaType != null) {
			response.setStatus(HttpServletResponse.SC_FORBIDDEN);
			response.setContentType(mediaType.toString());
			String format = responses.get(mediaType);
			response.getWriter().append(generateResponseBody(format, authException));
		}
		else {
			response.sendError(HttpServletResponse.SC_FORBIDDEN, authException.getMessage());
		}
	}

	/**
	 * Format the exception into a response. The format has been selected according to the accepted media types from the
	 * caller.
	 * 
	 * @param format the format to apply
	 * @param authException the exception to blend into the response
	 * @return a response body as a String
	 */
	protected String generateResponseBody(String format, AccessDeniedException authException) {
		return String.format(format, authException.getMessage());
	}

	private MediaType selectMediaType(String accept) {
		if (StringUtils.hasText(accept)) {
			for (MediaType mediaType : MediaType.parseMediaTypes(accept)) {
				for (MediaType candidate : responses.keySet()) {
					if (mediaType.includes(candidate)) {
						return mediaType;
					}
				}
			}
		}
		return null;
	}

}
