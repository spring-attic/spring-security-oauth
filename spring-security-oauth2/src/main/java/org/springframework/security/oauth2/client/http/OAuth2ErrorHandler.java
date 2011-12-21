package org.springframework.security.oauth2.client.http;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.web.client.DefaultResponseErrorHandler;

/**
 * Error handler specifically for an oauth 2 response.
 * @author Ryan Heaton
 */
public class OAuth2ErrorHandler extends DefaultResponseErrorHandler {

	@Override
	public void handleError(ClientHttpResponse response) throws IOException {

		// first try: www-authenticate error
		List<String> authenticateHeaders = response.getHeaders().get("WWW-Authenticate");
		if (authenticateHeaders != null) {
			for (String authenticateHeader : authenticateHeaders) {
				maybeThrowExceptionFromHeader(authenticateHeader, OAuth2AccessToken.BEARER_TYPE);
				maybeThrowExceptionFromHeader(authenticateHeader, OAuth2AccessToken.OAUTH2_TYPE);
			}
		}

		super.handleError(response);
	}

	private void maybeThrowExceptionFromHeader(String authenticateHeader, String headerType) {
		headerType = headerType.toLowerCase();
		if (authenticateHeader.toLowerCase().startsWith(headerType)) {
			Map<String, String> headerEntries = StringSplitUtils.splitEachArrayElementAndCreateMap(
					StringSplitUtils.splitIgnoringQuotes(authenticateHeader.substring(headerType.length()),
							','), "=", "\"");
			throw OAuth2Exception.valueOf(headerEntries);
		}		
	}

}
