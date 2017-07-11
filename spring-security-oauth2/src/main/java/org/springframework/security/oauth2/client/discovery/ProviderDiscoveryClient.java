/*
 * Copyright 2012-2017 the original author or authors.
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
package org.springframework.security.oauth2.client.discovery;

import org.springframework.util.Assert;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.Map;

/**
 * A client that is able to discover provider configuration information
 * as defined by the <i>OpenID Connect Discovery 1.0</i> specification.
 *
 * <p>
 * <b>NOTE:</b> This is a partial implementation that only discovers a small subset
 * of the available provider configuration information.
 *
 * @author Joe Grandja
 * @since 2.2
 * @see ProviderConfiguration
 * @see <a target="_blank" href="http://openid.net/specs/openid-connect-discovery-1_0.html">OpenID Connect Discovery 1.0</a>
 */
public class ProviderDiscoveryClient {
	private static final String PROVIDER_END_PATH = "/.well-known/openid-configuration";
	private static final String ISSUER_ATTR_NAME = "issuer";
	private static final String AUTHORIZATION_ENDPOINT_ATTR_NAME = "authorization_endpoint";
	private static final String TOKEN_ENDPOINT_ATTR_NAME = "token_endpoint";
	private static final String USERINFO_ENDPOINT_ATTR_NAME = "userinfo_endpoint";
	private static final String JWK_SET_URI_ATTR_NAME = "jwks_uri";
	private final RestTemplate restTemplate = new RestTemplate();
	private final URI providerLocation;

	public ProviderDiscoveryClient(String providerLocationUri) {
		Assert.hasText(providerLocationUri, "providerLocationUri cannot be empty");
		try {
			this.providerLocation = UriComponentsBuilder.fromHttpUrl(providerLocationUri)
					.path(PROVIDER_END_PATH)
					.build()
					.encode()
					.toUri();
		} catch (Exception ex) {
			throw new IllegalArgumentException("Invalid URI for providerLocationUri: " + ex.getMessage(), ex);
		}
	}

	/**
	 * Discover the provider configuration information.
	 *
	 * @throws RestClientException if the provider does not support discovery or for any HTTP-related errors
	 * @return the provider configuration information
	 */
	public ProviderConfiguration discover() {
		Map responseAttributes = this.restTemplate.getForObject(this.providerLocation, Map.class);

		ProviderConfiguration.Builder builder = new ProviderConfiguration.Builder();

		builder.issuer((String)responseAttributes.get(ISSUER_ATTR_NAME));
		builder.authorizationEndpoint((String)responseAttributes.get(AUTHORIZATION_ENDPOINT_ATTR_NAME));
		if (responseAttributes.containsKey(TOKEN_ENDPOINT_ATTR_NAME)) {
			builder.tokenEndpoint((String)responseAttributes.get(TOKEN_ENDPOINT_ATTR_NAME));
		}
		if (responseAttributes.containsKey(USERINFO_ENDPOINT_ATTR_NAME)) {
			builder.userInfoEndpoint((String)responseAttributes.get(USERINFO_ENDPOINT_ATTR_NAME));
		}
		if (responseAttributes.containsKey(JWK_SET_URI_ATTR_NAME)) {
			builder.jwkSetUri((String)responseAttributes.get(JWK_SET_URI_ATTR_NAME));
		}

		return builder.build();
	}
}