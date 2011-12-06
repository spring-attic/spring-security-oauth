package org.springframework.security.oauth2.provider.endpoint;

import org.springframework.security.crypto.codec.Base64;

import javax.ws.rs.core.HttpHeaders;
import java.io.UnsupportedEncodingException;
import java.util.List;
import java.util.Map;

public class JerseyAbstractEndPoint extends AbstractEndpoint {

	protected String[] findClientSecret(HttpHeaders headers, Map<String, String> parameters) {

		String clientSecret = parameters.get("client_secret");
		String clientId = parameters.get("client_id");
		if (clientSecret == null) {
			List<String> auths = headers.getRequestHeader("Authorization");
			if (auths != null) {

				for (String header : auths) {

					if (header.startsWith("Basic ")) {

						String token;
						try {
							byte[] base64Token = header.substring(6).trim().getBytes("UTF-8");
							token = new String(Base64.decode(base64Token), getCredentialsCharset());
						}
						catch (UnsupportedEncodingException e) {
							throw new IllegalStateException("Unsupported encoding", e);
						}

						String username = "";
						String password = "";
						int delim = token.indexOf(":");

						if (delim != -1) {
							username = token.substring(0, delim);
							password = token.substring(delim + 1);
						}

						if (clientId != null && !username.equals(clientId)) {
							continue;
						}
						clientId = username;
						clientSecret = password;
						break;

					}
				}
			}
		}
		return new String[] { clientId, clientSecret };


	}
}
