package org.springframework.security.oauth2.client;

import java.util.Arrays;

import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.security.oauth2.client.http.OAuth2ClientHttpRequestFactory;
import org.springframework.security.oauth2.client.http.OAuth2ErrorHandler;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.AccessTokenProvider;
import org.springframework.security.oauth2.client.token.AccessTokenProviderChain;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.implicit.ImplicitAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordAccessTokenProvider;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

/**
 * Rest template that is able to make OAuth2-authenticated REST requests with the credentials of the provided resource.
 * 
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class OAuth2RestTemplate extends RestTemplate {

	private final OAuth2ProtectedResourceDetails resource;

	private AccessTokenProvider accessTokenProvider = new AccessTokenProviderChain(Arrays.<AccessTokenProvider> asList(
			new AuthorizationCodeAccessTokenProvider(), new ImplicitAccessTokenProvider(),
			new ResourceOwnerPasswordAccessTokenProvider(), new ClientCredentialsAccessTokenProvider()));

	public OAuth2RestTemplate(OAuth2ProtectedResourceDetails resource) {
		this(new SimpleClientHttpRequestFactory(), resource);
	}

	public OAuth2RestTemplate(ClientHttpRequestFactory requestFactory, OAuth2ProtectedResourceDetails resource) {
		super();
		if (resource == null) {
			throw new IllegalArgumentException("An OAuth2 resource must be supplied.");
		}

		this.resource = resource;
		setRequestFactory(requestFactory);
		setErrorHandler(new OAuth2ErrorHandler(resource));
	}

	@Override
	public void setErrorHandler(ResponseErrorHandler errorHandler) {
		if (!(errorHandler instanceof OAuth2ErrorHandler)) {
			errorHandler = new OAuth2ErrorHandler(errorHandler, resource);
		}
		super.setErrorHandler(errorHandler);
	}

	@Override
	public void setRequestFactory(ClientHttpRequestFactory requestFactory) {
		if (!(requestFactory instanceof OAuth2ClientHttpRequestFactory)) {
			requestFactory = new OAuth2ClientHttpRequestFactory(requestFactory, accessTokenProvider, resource);
		}
		super.setRequestFactory(requestFactory);
	}

	public void setAccessTokenProvider(AccessTokenProvider accessTokenProvider) {
		this.accessTokenProvider = accessTokenProvider;
	}

}
