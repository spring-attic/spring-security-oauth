package org.springframework.security.oauth2.client.auth;

import java.io.UnsupportedEncodingException;

import org.springframework.http.client.ClientHttpRequest;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.oauth2.client.OAuth2ProtectedResourceDetails;
import org.springframework.util.MultiValueMap;

/**
 * Default implementation of the client authentication handler.
 * 
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class DefaultClientAuthenticationHandler implements ClientAuthenticationHandler {

	public void authenticateTokenRequest(OAuth2ProtectedResourceDetails resource, MultiValueMap<String, String> form,
			ClientHttpRequest request) {
		if (resource.isSecretRequired()) {
			ClientAuthenticationScheme scheme = ClientAuthenticationScheme.http_basic;
			if (resource.getClientAuthenticationScheme() != null) {
				scheme = ClientAuthenticationScheme.valueOf(resource.getClientAuthenticationScheme());
			}

			try {
				switch (scheme) {
				case http_basic:
					form.remove("client_id");
					form.remove("client_secret");
					request.getHeaders().add(
							"Authorization",
							String.format(
									"Basic %s",
									new String(Base64.encode(String.format("%s:%s", resource.getClientId(),
											resource.getClientSecret()).getBytes("UTF-8")), "UTF-8")));
					break;
				case form:
					form.add("client_id", resource.getClientId());
					form.add("client_secret", resource.getClientSecret());
					break;
				default:
					throw new IllegalStateException(
							"Default authentication handler doesn't know how to handle scheme: " + scheme);
				}
			} catch (UnsupportedEncodingException e) {
				throw new IllegalStateException(e);
			}
		}
	}
}
