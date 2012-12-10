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
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.oauth2.http.converter.jaxb.JaxbOAuth2ExceptionMessageConverter;
import org.springframework.web.HttpMediaTypeNotAcceptableException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.context.request.ServletWebRequest;

/**
 * Default implementation of {@link OAuth2ExceptionRenderer} that can render the exceptions using message converters
 * (just like regular Spring MVC endpoints). If the caller sends an appropriate Accept header he should get the right
 * result as long as an appropriate message converter is provided.
 * 
 * @author Dave Syer
 * 
 */
public class DefaultOAuth2ExceptionRenderer implements OAuth2ExceptionRenderer {

	private final Log logger = LogFactory.getLog(DefaultOAuth2ExceptionRenderer.class);

	private List<HttpMessageConverter<?>> messageConverters = geDefaultMessageConverters();

	public void setMessageConverters(List<HttpMessageConverter<?>> messageConverters) {
		this.messageConverters = messageConverters;
	}

	public void handleHttpEntityResponse(HttpEntity<?> responseEntity, ServletWebRequest webRequest) throws Exception {
		if (responseEntity == null) {
			return;
		}
		HttpInputMessage inputMessage = createHttpInputMessage(webRequest);
		HttpOutputMessage outputMessage = createHttpOutputMessage(webRequest);
		if (responseEntity instanceof ResponseEntity && outputMessage instanceof ServerHttpResponse) {
			((ServerHttpResponse) outputMessage).setStatusCode(((ResponseEntity<?>) responseEntity).getStatusCode());
		}
		HttpHeaders entityHeaders = responseEntity.getHeaders();
		if (!entityHeaders.isEmpty()) {
			outputMessage.getHeaders().putAll(entityHeaders);
		}
		Object body = responseEntity.getBody();
		if (body != null) {
			writeWithMessageConverters(body, inputMessage, outputMessage);
		}
		else {
			// flush headers
			outputMessage.getBody();
		}
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	private void writeWithMessageConverters(Object returnValue, HttpInputMessage inputMessage,
			HttpOutputMessage outputMessage) throws IOException, HttpMediaTypeNotAcceptableException {
		List<MediaType> acceptedMediaTypes = inputMessage.getHeaders().getAccept();
		if (acceptedMediaTypes.isEmpty()) {
			acceptedMediaTypes = Collections.singletonList(MediaType.ALL);
		}
		MediaType.sortByQualityValue(acceptedMediaTypes);
		Class<?> returnValueType = returnValue.getClass();
		List<MediaType> allSupportedMediaTypes = new ArrayList<MediaType>();
		for (MediaType acceptedMediaType : acceptedMediaTypes) {
			for (HttpMessageConverter messageConverter : messageConverters) {
				if (messageConverter.canWrite(returnValueType, acceptedMediaType)) {
					messageConverter.write(returnValue, acceptedMediaType, outputMessage);
					if (logger.isDebugEnabled()) {
						MediaType contentType = outputMessage.getHeaders().getContentType();
						if (contentType == null) {
							contentType = acceptedMediaType;
						}
						logger.debug("Written [" + returnValue + "] as \"" + contentType + "\" using ["
								+ messageConverter + "]");
					}
					return;
				}
			}
		}
		for (HttpMessageConverter messageConverter : messageConverters) {
			allSupportedMediaTypes.addAll(messageConverter.getSupportedMediaTypes());
		}
		throw new HttpMediaTypeNotAcceptableException(allSupportedMediaTypes);
	}

	private List<HttpMessageConverter<?>> geDefaultMessageConverters() {
		List<HttpMessageConverter<?>> result = new ArrayList<HttpMessageConverter<?>>();
		result.addAll(new RestTemplate().getMessageConverters());
		result.add(new JaxbOAuth2ExceptionMessageConverter());
		return result;
	}

	private HttpInputMessage createHttpInputMessage(NativeWebRequest webRequest) throws Exception {
		HttpServletRequest servletRequest = webRequest.getNativeRequest(HttpServletRequest.class);
		return new ServletServerHttpRequest(servletRequest);
	}

	private HttpOutputMessage createHttpOutputMessage(NativeWebRequest webRequest) throws Exception {
		HttpServletResponse servletResponse = (HttpServletResponse) webRequest.getNativeResponse();
		return new ServletServerHttpResponse(servletResponse);
	}

}
