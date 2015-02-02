package org.springframework.security.oauth2.client.token;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.security.oauth2.client.resource.OAuth2AccessDeniedException;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.auth.ClientAuthenticationHandler;
import org.springframework.security.oauth2.client.token.auth.DefaultClientAuthenticationHandler;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.http.converter.FormOAuth2AccessTokenMessageConverter;
import org.springframework.security.oauth2.http.converter.FormOAuth2ExceptionHttpMessageConverter;
import org.springframework.util.Assert;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.HttpMessageConverterExtractor;
import org.springframework.web.client.RequestCallback;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.ResponseExtractor;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

/**
 * Base support logic for obtaining access tokens.
 * 
 * @author Ryan Heaton
 * @author Dave Syer
 */
public abstract class OAuth2AccessTokenSupport {

	protected final Log logger = LogFactory.getLog(getClass());

	private static final FormHttpMessageConverter FORM_MESSAGE_CONVERTER = new FormHttpMessageConverter();

	private RestOperations restTemplate;

	private List<HttpMessageConverter<?>> messageConverters;

	private ClientAuthenticationHandler authenticationHandler = new DefaultClientAuthenticationHandler();

	private ResponseErrorHandler responseErrorHandler = new AccessTokenErrorHandler();

	private List<ClientHttpRequestInterceptor> interceptors = new ArrayList<ClientHttpRequestInterceptor>();
	
	private RequestEnhancer tokenRequestEnhancer = new DefaultRequestEnhancer();
	
	/**
	 * Sets the request interceptors that this accessor should use.
	 */
	public void setInterceptors(List<ClientHttpRequestInterceptor> interceptors) {
		this.interceptors = interceptors;
	}
	
	/**
	 * A custom enhancer for the access token request
	 * @param tokenRequestEnhancer
	 */
	public void setTokenRequestEnhancer(RequestEnhancer tokenRequestEnhancer) {
		this.tokenRequestEnhancer = tokenRequestEnhancer;
	}

	private ClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory() {
		@Override
		protected void prepareConnection(HttpURLConnection connection, String httpMethod)
				throws IOException {
			super.prepareConnection(connection, httpMethod);
			connection.setInstanceFollowRedirects(false);
			connection.setUseCaches(false);
		}
	};

	protected RestOperations getRestTemplate() {
		if (restTemplate == null) {
			synchronized (this) {
				if (restTemplate == null) {
					RestTemplate restTemplate = new RestTemplate();
					restTemplate.setErrorHandler(getResponseErrorHandler());
					restTemplate.setRequestFactory(requestFactory);
					restTemplate.setInterceptors(interceptors);
					this.restTemplate = restTemplate;
				}
			}
		}
		if (messageConverters == null) {
			setMessageConverters(new RestTemplate().getMessageConverters());
		}
		return restTemplate;
	}

	public void setAuthenticationHandler(ClientAuthenticationHandler authenticationHandler) {
		this.authenticationHandler = authenticationHandler;
	}

	public void setMessageConverters(List<HttpMessageConverter<?>> messageConverters) {
		this.messageConverters = new ArrayList<HttpMessageConverter<?>>(messageConverters);
		this.messageConverters.add(new FormOAuth2AccessTokenMessageConverter());
		this.messageConverters.add(new FormOAuth2ExceptionHttpMessageConverter());
	}

	protected OAuth2AccessToken retrieveToken(AccessTokenRequest request, OAuth2ProtectedResourceDetails resource,
			MultiValueMap<String, String> form, HttpHeaders headers) throws OAuth2AccessDeniedException {

		try {
			// Prepare headers and form before going into rest template call in case the URI is affected by the result
			authenticationHandler.authenticateTokenRequest(resource, form, headers);
			// Opportunity to customize form and headers
			tokenRequestEnhancer.enhance(request, resource, form, headers);
			final AccessTokenRequest copy = request;

			final ResponseExtractor<OAuth2AccessToken> delegate = getResponseExtractor();
			ResponseExtractor<OAuth2AccessToken> extractor = new ResponseExtractor<OAuth2AccessToken>() {
				@Override
				public OAuth2AccessToken extractData(ClientHttpResponse response) throws IOException {
					if (response.getHeaders().containsKey("Set-Cookie")) {
						copy.setCookie(response.getHeaders().getFirst("Set-Cookie"));
					}
					return delegate.extractData(response);
				}
			};
			return getRestTemplate().execute(getAccessTokenUri(resource, form), getHttpMethod(),
					getRequestCallback(resource, form, headers), extractor , form.toSingleValueMap());

		}
		catch (OAuth2Exception oe) {
			throw new OAuth2AccessDeniedException("Access token denied.", resource, oe);
		}
		catch (RestClientException rce) {
			throw new OAuth2AccessDeniedException("Error requesting access token.", resource, rce);
		}

	}

	protected HttpMethod getHttpMethod() {
		return HttpMethod.POST;
	}

	protected String getAccessTokenUri(OAuth2ProtectedResourceDetails resource, MultiValueMap<String, String> form) {

		String accessTokenUri = resource.getAccessTokenUri();

		if (logger.isDebugEnabled()) {
			logger.debug("Retrieving token from " + accessTokenUri);
		}

		StringBuilder builder = new StringBuilder(accessTokenUri);

		if (getHttpMethod() == HttpMethod.GET) {
			String separator = "?";
			if (accessTokenUri.contains("?")) {
				separator = "&";
			}

			for (String key : form.keySet()) {
				builder.append(separator);
				builder.append(key + "={" + key + "}");
				separator = "&";
			}
		}

		return builder.toString();

	}

	protected ResponseErrorHandler getResponseErrorHandler() {
		return responseErrorHandler;
	}

	/**
	 * Set the request factory that this template uses for obtaining {@link ClientHttpRequest HttpRequests}.
	 */
	public void setRequestFactory(ClientHttpRequestFactory requestFactory) {
		Assert.notNull(requestFactory, "'requestFactory' must not be null");
		this.requestFactory = requestFactory;
	}

	protected ResponseExtractor<OAuth2AccessToken> getResponseExtractor() {
		getRestTemplate(); // force initialization
		return new HttpMessageConverterExtractor<OAuth2AccessToken>(OAuth2AccessToken.class, this.messageConverters);
	}

	protected RequestCallback getRequestCallback(OAuth2ProtectedResourceDetails resource,
			MultiValueMap<String, String> form, HttpHeaders headers) {
		return new OAuth2AuthTokenCallback(form, headers);
	}

	/**
	 * Request callback implementation that writes the given object to the request stream.
	 */
	private class OAuth2AuthTokenCallback implements RequestCallback {

		private final MultiValueMap<String, String> form;

		private final HttpHeaders headers;

		private OAuth2AuthTokenCallback(MultiValueMap<String, String> form, HttpHeaders headers) {
			this.form = form;
			this.headers = headers;
		}

		public void doWithRequest(ClientHttpRequest request) throws IOException {
			request.getHeaders().putAll(this.headers);
			request.getHeaders().setAccept(
					Arrays.asList(MediaType.APPLICATION_JSON, MediaType.APPLICATION_FORM_URLENCODED));
			logger.debug("Encoding and sending form: " + form);
			FORM_MESSAGE_CONVERTER.write(this.form, MediaType.APPLICATION_FORM_URLENCODED, request);
		}
	}

	private class AccessTokenErrorHandler extends DefaultResponseErrorHandler {

		@SuppressWarnings("unchecked")
		@Override
		public void handleError(ClientHttpResponse response) throws IOException {
			for (HttpMessageConverter<?> converter : messageConverters) {
				if (converter.canRead(OAuth2Exception.class, response.getHeaders().getContentType())) {
					OAuth2Exception ex;
					try {
						ex = ((HttpMessageConverter<OAuth2Exception>) converter).read(OAuth2Exception.class, response);
					}
					catch (Exception e) {
						// ignore
						continue;
					}
					throw ex;
				}
			}
			super.handleError(response);
		}

	}

}
