package org.springframework.security.oauth2.consumer;

import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.oauth.common.StringSplitUtils;
import org.springframework.security.oauth2.common.DefaultOAuth2SerializationService;
import org.springframework.security.oauth2.common.OAuth2SerializationService;
import org.springframework.web.client.DefaultResponseErrorHandler;

import java.io.IOException;
import java.util.List;
import java.util.Map;

/**
 * Error handler specifically for an oauth 2 response.
 * @author Ryan Heaton
 */
public class OAuth2ErrorHandler extends DefaultResponseErrorHandler {

	public static final String AUTH_HEADER = "oauth2 ";
	private OAuth2SerializationService serializationService = new DefaultOAuth2SerializationService();

	@Override
	public void handleError(ClientHttpResponse response) throws IOException {

		// first try: www-authenticate error
		List<String> authenticateHeaders = response.getHeaders().get("WWW-Authenticate");
		if (authenticateHeaders != null) {
			for (String authenticateHeader : authenticateHeaders) {
				if (authenticateHeader.toLowerCase().startsWith(AUTH_HEADER)) {
					Map<String, String> headerEntries = StringSplitUtils.splitEachArrayElementAndCreateMap(
							StringSplitUtils.splitIgnoringQuotes(authenticateHeader.substring(AUTH_HEADER.length()),
									','), "=", "\"");
					throw getSerializationService().deserializeError(headerEntries);
				}
			}
		}

		super.handleError(response);
	}

	public OAuth2SerializationService getSerializationService() {
		return serializationService;
	}

	public void setSerializationService(OAuth2SerializationService serializationService) {
		this.serializationService = serializationService;
	}
}
