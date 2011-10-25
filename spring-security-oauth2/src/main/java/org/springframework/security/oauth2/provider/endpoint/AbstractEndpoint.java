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
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.AbstractHttpMessageConverter;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.error.DefaultProviderExceptionHandler;
import org.springframework.security.oauth2.provider.error.ProviderExceptionHandler;
import org.springframework.util.FileCopyUtils;
import org.springframework.web.HttpMediaTypeNotAcceptableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.context.request.ServletWebRequest;

/**
 * @author Dave Syer
 * 
 */
public class AbstractEndpoint implements InitializingBean {

	protected final Log logger = LogFactory.getLog(getClass());

	private ProviderExceptionHandler providerExceptionHandler = new DefaultProviderExceptionHandler();

	private List<HttpMessageConverter<?>> messageConverters = null;

	private TokenGranter tokenGranter;

	public void setMessageConverters(List<HttpMessageConverter<?>> messageConverters) {
		this.messageConverters = messageConverters;
	}

	public void setProviderExceptionHandler(ProviderExceptionHandler providerExceptionHandler) {
		this.providerExceptionHandler = providerExceptionHandler;
	}

	public void setTokenGranter(TokenGranter tokenGranter) {
		this.tokenGranter = tokenGranter;
	}
	
	protected TokenGranter getTokenGranter() {
		return tokenGranter;
	}

	public void afterPropertiesSet() throws Exception {
		if (this.messageConverters == null) {
			this.messageConverters = geDefaultMessageConverters();
		}
	}

	@ExceptionHandler(OAuth2Exception.class)
	public void handleException(OAuth2Exception e, ServletWebRequest webRequest) throws Exception {
		handleHttpEntityResponse(providerExceptionHandler.handle(e), webRequest);
	}

	private void handleHttpEntityResponse(HttpEntity<?> responseEntity, ServletWebRequest webRequest) throws Exception {
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
		result.add(new PreconvertedHttpMessageConverter());
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

	private static class PreconvertedHttpMessageConverter extends AbstractHttpMessageConverter<String> {

		@Override
		protected boolean supports(Class<?> clazz) {
			return CharSequence.class.isAssignableFrom(clazz);
		}

		@Override
		protected boolean canWrite(MediaType mediaType) {
			return true;
		}

		@Override
		protected String readInternal(Class<? extends String> clazz, HttpInputMessage inputMessage) throws IOException,
				HttpMessageNotReadableException {
			return FileCopyUtils.copyToString(new InputStreamReader(inputMessage.getBody()));
		}

		@Override
		protected void writeInternal(String t, HttpOutputMessage outputMessage) throws IOException,
				HttpMessageNotWritableException {
			FileCopyUtils.copy(t, new OutputStreamWriter(outputMessage.getBody()));
		}

	}

}