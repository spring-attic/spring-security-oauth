/*
 * Copyright 20013-2014 the original author or authors.
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

package demo;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.springframework.http.HttpRequest;
import org.springframework.http.MediaType;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.security.oauth2.http.converter.jaxb.JaxbOAuth2AccessTokenMessageConverter;
import org.springframework.security.oauth2.http.converter.jaxb.JaxbOAuth2ExceptionMessageConverter;

/**
 * @author Dave Syer
 *
 */
public class Converters {

	public static Collection<HttpMessageConverter<?>> getJaxbConverters() {
		Collection<HttpMessageConverter<?>> converters = new ArrayList<>();
		converters.add(new JaxbOAuth2AccessTokenMessageConverter());
		converters.add(new JaxbOAuth2ExceptionMessageConverter());
		return converters;
	}

	public static List<ClientHttpRequestInterceptor> getInterceptors() {
		return Arrays.<ClientHttpRequestInterceptor> asList(new AcceptHeaderInterceptor(MediaType.APPLICATION_XML));
	}

	private static class AcceptHeaderInterceptor implements ClientHttpRequestInterceptor {

		private MediaType type;

		public AcceptHeaderInterceptor(MediaType type) {
			this.type = type;
		}

		@Override
		public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution)
				throws IOException {
			request.getHeaders().add("Accept", type.toString());
			return execution.execute(request, body);
		}

	}
}
