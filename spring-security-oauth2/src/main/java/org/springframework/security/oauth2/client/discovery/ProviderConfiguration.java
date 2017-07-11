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

import java.net.MalformedURLException;
import java.net.URL;

/**
 * Configuration information for an <i>OAuth 2.0 Provider</i>.
 *
 * @author Joe Grandja
 * @since 2.2
 * @see ProviderDiscoveryClient
 * @see <a target="_blank" href="http://openid.net/specs/openid-connect-discovery-1_0.html">OpenID Connect Discovery 1.0</a>
 */
public class ProviderConfiguration {
	private URL issuer;
	private URL authorizationEndpoint;
	private URL tokenEndpoint;
	private URL userInfoEndpoint;
	private URL jwkSetUri;

	public URL getIssuer() {
		return this.issuer;
	}

	public URL getAuthorizationEndpoint() {
		return this.authorizationEndpoint;
	}

	public URL getTokenEndpoint() {
		return this.tokenEndpoint;
	}

	public URL getUserInfoEndpoint() {
		return this.userInfoEndpoint;
	}

	public URL getJwkSetUri() {
		return this.jwkSetUri;
	}

	public static class Builder {
		private ProviderConfiguration providerConfiguration = new ProviderConfiguration();

		public Builder() {
		}

		public void issuer(String isssuer) {
			this.providerConfiguration.issuer = this.toURL(isssuer);
		}

		public void authorizationEndpoint(String authorizationEndpoint) {
			this.providerConfiguration.authorizationEndpoint = this.toURL(authorizationEndpoint);
		}

		public void tokenEndpoint(String tokenEndpoint) {
			this.providerConfiguration.tokenEndpoint = this.toURL(tokenEndpoint);
		}

		public void userInfoEndpoint(String userInfoEndpoint) {
			this.providerConfiguration.userInfoEndpoint = this.toURL(userInfoEndpoint);
		}

		public void jwkSetUri(String jwkSetUri) {
			this.providerConfiguration.jwkSetUri = this.toURL(jwkSetUri);
		}

		public ProviderConfiguration build() {
			return this.providerConfiguration;
		}

		private URL toURL(String urlStr) {
			try {
				return new URL(urlStr);
			} catch (MalformedURLException ex) {
				throw new IllegalArgumentException("Unable to convert '" + urlStr + "' to URL: " + ex.getMessage(), ex);
			}
		}
	}
}