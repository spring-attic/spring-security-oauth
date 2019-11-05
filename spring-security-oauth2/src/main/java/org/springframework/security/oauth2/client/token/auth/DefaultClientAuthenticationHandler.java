package org.springframework.security.oauth2.client.token.auth;

import java.io.UnsupportedEncodingException;

import org.springframework.http.HttpHeaders;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.common.AuthenticationScheme;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

/**
 * Default implementation of the client authentication handler.
 *
 * <p>
 * @deprecated See the <a href="https://github.com/spring-projects/spring-security/wiki/OAuth-2.0-Migration-Guide">OAuth 2.0 Migration Guide</a> for Spring Security 5.
 *
 * @author Ryan Heaton
 * @author Dave Syer
 */
@Deprecated
public class DefaultClientAuthenticationHandler implements ClientAuthenticationHandler {

	public void authenticateTokenRequest(OAuth2ProtectedResourceDetails resource, MultiValueMap<String, String> form,
			HttpHeaders headers) {
		if (resource.isAuthenticationRequired()) {
			AuthenticationScheme scheme = AuthenticationScheme.header;
			if (resource.getClientAuthenticationScheme() != null) {
				scheme = resource.getClientAuthenticationScheme();
			}

			try {
				String clientSecret = resource.getClientSecret();
				clientSecret = clientSecret == null ? "" : clientSecret;
				switch (scheme) {
				case header:
					form.remove("client_secret");
					headers.add(
							"Authorization",
							String.format(
									"Basic %s",
									new String(Base64.encode(String.format("%s:%s", resource.getClientId(),
											clientSecret).getBytes("UTF-8")), "UTF-8")));
					break;
				case form:
				case query:
					form.set("client_id", resource.getClientId());
					if (StringUtils.hasText(clientSecret)) {
						form.set("client_secret", clientSecret);
					}
					break;
				default:
					throw new IllegalStateException(
							"Default authentication handler doesn't know how to handle scheme: " + scheme);
				}
			}
			catch (UnsupportedEncodingException e) {
				throw new IllegalStateException(e);
			}
		}
	}
}
