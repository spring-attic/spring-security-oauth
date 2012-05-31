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
package org.springframework.security.oauth2.client.http;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.HttpMessageConverterExtractor;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

/**
 * Error handler specifically for an oauth 2 response.
 * @author Ryan Heaton
 */
public class OAuth2ErrorHandler implements ResponseErrorHandler {

	private final ResponseErrorHandler errorHandler;

	private final OAuth2ProtectedResourceDetails resource;

	private List<HttpMessageConverter<?>> messageConverters = new RestTemplate().getMessageConverters();

	/**
	 * Construct an error handler that can deal with OAuth2 concerns before handling the error in the default fashion.
	 */
	public OAuth2ErrorHandler(OAuth2ProtectedResourceDetails resource) {
		this(new DefaultResponseErrorHandler(), resource);
	}

	/**
	 * @param messageConverters the messageConverters to set
	 */
	public void setMessageConverters(List<HttpMessageConverter<?>> messageConverters) {
		this.messageConverters = messageConverters;
	}

	/**
	 * Construct an error handler that can deal with OAuth2 concerns before delegating to acustom handler.
	 * 
	 * @param errorHandler a delegate handler
	 */
	public OAuth2ErrorHandler(ResponseErrorHandler errorHandler, OAuth2ProtectedResourceDetails resource) {
		this.resource = resource;
		this.errorHandler = errorHandler;
	}

	public boolean hasError(ClientHttpResponse response) throws IOException {
		return this.errorHandler.hasError(response);
	}

	public void handleError(ClientHttpResponse response) throws IOException {

		HttpMessageConverterExtractor<OAuth2Exception> extractor = new HttpMessageConverterExtractor<OAuth2Exception>(
				OAuth2Exception.class, messageConverters);
		try {
			OAuth2Exception body = extractor.extractData(response);
			if (body != null) {
				// If we can get an OAuth2Exception already from the body, it is likely to have more information than
				// the header does, so just re-throw it here.
				throw body;
			}
		}
		catch (RestClientException e) {
			// ignore
		}

		// first try: www-authenticate error
		List<String> authenticateHeaders = response.getHeaders().get("WWW-Authenticate");
		if (authenticateHeaders != null) {
			for (String authenticateHeader : authenticateHeaders) {
				maybeThrowExceptionFromHeader(authenticateHeader, OAuth2AccessToken.BEARER_TYPE);
				maybeThrowExceptionFromHeader(authenticateHeader, OAuth2AccessToken.OAUTH2_TYPE);
			}
		}

		// then delegate to the custom handler
		errorHandler.handleError(response);
	}

	private void maybeThrowExceptionFromHeader(String authenticateHeader, String headerType) {
		headerType = headerType.toLowerCase();
		if (authenticateHeader.toLowerCase().startsWith(headerType)) {
			Map<String, String> headerEntries = StringSplitUtils.splitEachArrayElementAndCreateMap(
					StringSplitUtils.splitIgnoringQuotes(authenticateHeader.substring(headerType.length()), ','), "=",
					"\"");
			OAuth2Exception ex = OAuth2Exception.valueOf(headerEntries);
			if (ex instanceof InvalidTokenException) {
				// Special case: an invalid token can be renewed so tell the caller what to do
				throw new AccessTokenRequiredException(resource);
			}
			throw ex;
		}
	}

}
