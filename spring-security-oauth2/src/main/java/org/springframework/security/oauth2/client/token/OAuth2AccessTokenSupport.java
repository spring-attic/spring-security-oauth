package org.springframework.security.oauth2.client.token;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.util.Arrays;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.http.converter.AbstractHttpMessageConverter;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.auth.ClientAuthenticationHandler;
import org.springframework.security.oauth2.client.token.auth.DefaultClientAuthenticationHandler;
import org.springframework.security.oauth2.common.DefaultOAuth2SerializationService;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2SerializationService;
import org.springframework.security.oauth2.common.exceptions.OAuth2AccessDeniedException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.common.exceptions.SerializationException;
import org.springframework.util.Assert;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.HttpMessageConverterExtractor;
import org.springframework.web.client.RequestCallback;
import org.springframework.web.client.ResponseExtractor;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

/**
 * Base support logic for obtaining access tokens.
 * 
 * @author Ryan Heaton
 * @author Dave Syer
 */
public abstract class OAuth2AccessTokenSupport implements InitializingBean {

	protected final Log logger = LogFactory.getLog(getClass());

	private static final FormHttpMessageConverter FORM_MESSAGE_CONVERTER = new FormHttpMessageConverter();

	private final RestTemplate restTemplate;

	private OAuth2SerializationService serializationService = new DefaultOAuth2SerializationService();

	private ClientAuthenticationHandler authenticationHandler = new DefaultClientAuthenticationHandler();

	protected OAuth2AccessTokenSupport() {
		this.restTemplate = new RestTemplate();
		this.restTemplate.setErrorHandler(new AccessTokenErrorHandler());
		this.restTemplate.setRequestFactory(new SimpleClientHttpRequestFactory() {
			@Override
			protected void prepareConnection(HttpURLConnection connection, String httpMethod) throws IOException {
				super.prepareConnection(connection, httpMethod);
				connection.setInstanceFollowRedirects(false);
			}
		});
	}

	public void afterPropertiesSet() throws Exception {
		Assert.notNull(restTemplate, "A RestTemplate is required.");
		Assert.notNull(serializationService, "OAuth2 serialization service is required.");
	}

	protected RestTemplate getRestTemplate() {
		return restTemplate;
	}

	protected OAuth2SerializationService getSerializationService() {
		return serializationService;
	}

	public void setSerializationService(OAuth2SerializationService serializationService) {
		this.serializationService = serializationService;
	}

	protected ClientAuthenticationHandler getAuthenticationHandler() {
		return authenticationHandler;
	}

	public void setAuthenticationHandler(ClientAuthenticationHandler authenticationHandler) {
		this.authenticationHandler = authenticationHandler;
	}

	protected OAuth2AccessToken retrieveToken(MultiValueMap<String, String> form,
			OAuth2ProtectedResourceDetails resource) {

		try {
			// Prepare headers and form before going into rest template call in case the URI is affected by the result
			HttpHeaders headers = new HttpHeaders();
			getAuthenticationHandler().authenticateTokenRequest(resource, form, headers);

			return getRestTemplate().execute(getAccessTokenUri(resource, form), getHttpMethod(),
					getRequestCallback(resource, form, headers), getResponseExtractor(), form.toSingleValueMap());

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

	protected ResponseExtractor<OAuth2AccessToken> getResponseExtractor() {
		return new HttpMessageConverterExtractor<OAuth2AccessToken>(OAuth2AccessToken.class,
				Arrays.<HttpMessageConverter<?>> asList(new OAuth2AccessTokenMessageConverter()));
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
			FORM_MESSAGE_CONVERTER.write(this.form, MediaType.APPLICATION_FORM_URLENCODED, request);
		}
	}

	private class AccessTokenErrorHandler extends DefaultResponseErrorHandler {

		@Override
		public void handleError(ClientHttpResponse response) throws IOException {
			MediaType contentType = response.getHeaders().getContentType();
			if (contentType != null
					&& (response.getStatusCode().value() == 400 || response.getStatusCode().value() == 401)) {
				if (MediaType.APPLICATION_JSON.includes(contentType)) {
					try {
						throw getSerializationService().deserializeJsonError(response.getBody());
					}
					catch (SerializationException e) {
						throw new OAuth2Exception(
								"Error getting the access token, and unable to read the details of the error in the JSON response.",
								e);
					}
				}
				else if (MediaType.APPLICATION_FORM_URLENCODED.includes(contentType)) {
					MultiValueMap<String, String> map = FORM_MESSAGE_CONVERTER.read(null, response);
					throw getSerializationService().deserializeError(map.toSingleValueMap());
				}
			}

			super.handleError(response);
		}

	}

	private class OAuth2AccessTokenMessageConverter extends AbstractHttpMessageConverter<OAuth2AccessToken> {

		private OAuth2AccessTokenMessageConverter() {
			super(new MediaType("*", "*"));
		}

		@Override
		protected boolean supports(Class<?> clazz) {
			return OAuth2AccessToken.class.isAssignableFrom(clazz);
		}

		@Override
		protected OAuth2AccessToken readInternal(Class<? extends OAuth2AccessToken> clazz, HttpInputMessage response)
				throws IOException, HttpMessageNotReadableException {
			MediaType contentType = response.getHeaders().getContentType();
			if (contentType != null && MediaType.APPLICATION_JSON.includes(contentType)) {
				try {
					return getSerializationService().deserializeJsonAccessToken(response.getBody());
				}
				catch (SerializationException e) {
					throw new OAuth2Exception(
							"Error getting the access token, and unable to read the details of the error in the JSON response.",
							e);
				}
			}
			else {
				// the spec currently says json is required, but facebook, for example, still returns form-encoded.
				MultiValueMap<String, String> map = FORM_MESSAGE_CONVERTER.read(null, response);
				return getSerializationService().deserializeAccessToken(map.toSingleValueMap());
			}
		}

		@Override
		protected void writeInternal(OAuth2AccessToken oAuth2AccessToken, HttpOutputMessage outputMessage)
				throws IOException, HttpMessageNotWritableException {
			throw new HttpMessageNotWritableException("Access token support shouldn't need to write access tokens.");
		}
	}
}
