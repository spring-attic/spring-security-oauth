/*
 * Copyright 2006-2014 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.springframework.security.oauth.provider.filter;

import org.apache.commons.codec.DecoderException;
import org.springframework.security.oauth.common.OAuthParameter;
import org.springframework.security.oauth.common.OAuthParameters;
import org.springframework.security.oauth.common.StringSplitUtils;
import org.springframework.security.oauth.provider.OAuthProviderSupport;

import javax.servlet.http.HttpServletRequest;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;

import static org.springframework.security.oauth.common.OAuthCodec.oauthDecode;
import static org.springframework.security.oauth.common.OAuthCodec.oauthEncode;

/**
 * Utility for common logic for supporting an OAuth provider.
 *
 * @author Ryan Heaton
 * @author <a rel="author" href="http://autayeu.com/">Aliaksandr Autayeu</a>
 */
public class CoreOAuthProviderSupport implements OAuthProviderSupport {

	private String baseUrl = null;

	public CoreOAuthProviderSupport() {
	}

	/**
	 * Parses and returns the OAuth parameters from the request. First tries header, then request parameters.
	 *
	 * @param request The servlet request.
	 * @return parsed OAuth parameters
	 */
	@Override
	public OAuthParameters parseParameters(HttpServletRequest request) {
		OAuthParameters parameters = parseHeaderParameters(request);

		if (parameters == null) {
			// if there is no header authorization parameters,
			// then the OAuth parameters are the supported OAuth request parameters.
			parameters = new OAuthParameters();
			parameters.setConsumerKey(request.getParameter(OAuthParameter.oauth_consumer_key.toString()));
			parameters.setToken(request.getParameter(OAuthParameter.oauth_token.toString()));
			// was ignored previously
			parameters.setTokenSecret(request.getParameter(OAuthParameter.oauth_token_secret.toString()));
			parameters.setSignatureMethod(request.getParameter(OAuthParameter.oauth_signature_method.toString()));
			parameters.setSignature(request.getParameter(OAuthParameter.oauth_signature.toString()));
			parameters.setTimestamp(request.getParameter(OAuthParameter.oauth_timestamp.toString()));
			parameters.setNonce(request.getParameter(OAuthParameter.oauth_nonce.toString()));
			parameters.setVersion(request.getParameter(OAuthParameter.oauth_version.toString()));
			parameters.setCallback(request.getParameter(OAuthParameter.oauth_callback.toString()));
			// was ignored previously
			parameters.setCallbackConfirmed(request.getParameter(OAuthParameter.oauth_callback_confirmed.toString()));
			parameters.setVerifier(request.getParameter(OAuthParameter.oauth_verifier.toString()));
		}

		return parameters;
	}

	/**
	 * Parse the OAuth header parameters. The parameters will be oauth-decoded.
	 *
	 * @param request The request.
	 * @return The parsed parameters, or null if no OAuth authorization header was supplied.
	 */
	protected OAuthParameters parseHeaderParameters(HttpServletRequest request) {
		String header = null;
		Enumeration<String> headers = request.getHeaders("Authorization");
		if (null != headers) {
			while (headers.hasMoreElements()) {
				String value = headers.nextElement();
				if ((value.toLowerCase().startsWith("oauth "))) {
					header = value;
					break;
				}
			}
		}

		OAuthParameters parameters = null;
		if (header != null) {
			String authHeaderValue = header.substring(6);

			// create a map of the authorization header values per OAuth Core 1.0, section 5.4.1
			Map<String, String> headerEntries = StringSplitUtils.prepareHeaderForParsing(authHeaderValue);
			Map<String, String> parsedEntries = new HashMap<String, String>();
			if (null != headerEntries) {
				for (Map.Entry<String, String> entry : headerEntries.entrySet()) {
					try {
						String key = oauthDecode(entry.getKey());
						String value = oauthDecode(entry.getValue());
						parsedEntries.put(key, value);
					}
					catch (DecoderException e) {
						throw new IllegalStateException(e);
					}
				}
			}

			parameters = new OAuthParameters();
			parameters.setConsumerKey(parsedEntries.get(OAuthParameter.oauth_consumer_key.toString()));
			parameters.setToken(parsedEntries.get(OAuthParameter.oauth_token.toString()));
			parameters.setTokenSecret(parsedEntries.get(OAuthParameter.oauth_token_secret.toString()));
			parameters.setSignatureMethod(parsedEntries.get(OAuthParameter.oauth_signature_method.toString()));
			parameters.setSignature(parsedEntries.get(OAuthParameter.oauth_signature.toString()));
			parameters.setTimestamp(parsedEntries.get(OAuthParameter.oauth_timestamp.toString()));
			parameters.setNonce(parsedEntries.get(OAuthParameter.oauth_nonce.toString()));
			parameters.setVersion(parsedEntries.get(OAuthParameter.oauth_version.toString()));
			parameters.setCallback(parsedEntries.get(OAuthParameter.oauth_callback.toString()));
			parameters.setCallbackConfirmed(parsedEntries.get(OAuthParameter.oauth_callback_confirmed.toString()));
			parameters.setVerifier(parsedEntries.get(OAuthParameter.oauth_verifier.toString()));
			parameters.setRealm(parsedEntries.get("realm"));
		}

		return parameters;
	}

	@Override
	public String getSignatureBaseString(HttpServletRequest request) {
		SortedMap<String, SortedSet<String>> significantParameters = loadSignificantParametersForSignatureBaseString(request);

		// now concatenate them into a single query string according to the spec.
		StringBuilder queryString = new StringBuilder();
		Iterator<Map.Entry<String, SortedSet<String>>> paramIt = significantParameters.entrySet().iterator();
		while (paramIt.hasNext()) {
			Map.Entry<String, SortedSet<String>> sortedParameter = paramIt.next();
			Iterator<String> valueIt = sortedParameter.getValue().iterator();
			while (valueIt.hasNext()) {
				String parameterValue = valueIt.next();
				queryString.append(sortedParameter.getKey()).append('=').append(parameterValue);
				if (paramIt.hasNext() || valueIt.hasNext()) {
					queryString.append('&');
				}
			}
		}

		String url = getBaseUrl(request);
		if (url == null) {
			// if no URL is configured, then we'll attempt to reconstruct the URL.  This may be inaccurate.
			url = request.getRequestURL().toString();
		}
		url = normalizeUrl(url);
		url = oauthEncode(url);

		String method = request.getMethod().toUpperCase();
		return method + '&' + url + '&' + oauthEncode(queryString.toString());
	}

	/**
	 * Normalize the URL for use in the signature. The OAuth spec says the URL protocol and host are to be lower-case,
	 * and the query and fragments are to be stripped.
	 *
	 * @param url The URL.
	 * @return The URL normalized for use in the signature.
	 */
	protected String normalizeUrl(String url) {
		try {
			URL requestURL = new URL(url);
			StringBuilder normalized = new StringBuilder(requestURL.getProtocol().toLowerCase()).append("://").append(requestURL.getHost().toLowerCase());
			if ((requestURL.getPort() >= 0) && (requestURL.getPort() != requestURL.getDefaultPort())) {
				normalized.append(":").append(requestURL.getPort());
			}
			normalized.append(requestURL.getPath());
			return normalized.toString();
		}
		catch (MalformedURLException e) {
			throw new IllegalStateException("Illegal URL for calculating the OAuth signature.", e);
		}
	}

	/**
	 * Loads the significant parameters (name-to-value map) that are to be used to calculate the signature base string.
	 * The parameters will be encoded, per the spec section 9.1.
	 *
	 * @param request The request.
	 * @return The significant parameters.
	 */
	protected SortedMap<String, SortedSet<String>> loadSignificantParametersForSignatureBaseString(HttpServletRequest request) {
		// first collect the relevant parameters...
		SortedMap<String, SortedSet<String>> significantParameters = new TreeMap<String, SortedSet<String>>();
		// first pull from the request...
		Enumeration parameterNames = request.getParameterNames();
		while (parameterNames.hasMoreElements()) {
			String parameterName = (String) parameterNames.nextElement();
			String[] values = request.getParameterValues(parameterName);
			if (values == null) {
				values = new String[]{""};
			}

			parameterName = oauthEncode(parameterName);
			for (String parameterValue : values) {
				if (parameterValue == null) {
					parameterValue = "";
				}

				parameterValue = oauthEncode(parameterValue);
				SortedSet<String> significantValues = significantParameters.get(parameterName);
				if (significantValues == null) {
					significantValues = new TreeSet<String>();
					significantParameters.put(parameterName, significantValues);
				}
				significantValues.add(parameterValue);
			}
		}

		// then take into account the header parameter values, ignoring realm and signature...
		OAuthParameters oauthParams = parseHeaderParameters(request);

		if (null != oauthParams) {
			if (null != oauthParams.getConsumerKey()) {
				addToSignificantParameters(significantParameters, OAuthParameter.oauth_consumer_key.toString(), oauthParams.getConsumerKey());
			}
			if (null != oauthParams.getToken()) {
				addToSignificantParameters(significantParameters, OAuthParameter.oauth_token.toString(), oauthParams.getToken());
			}
			if (null != oauthParams.getTokenSecret()) {
				addToSignificantParameters(significantParameters, OAuthParameter.oauth_token_secret.toString(), oauthParams.getTokenSecret());
			}
			if (null != oauthParams.getSignatureMethod()) {
				addToSignificantParameters(significantParameters, OAuthParameter.oauth_signature_method.toString(), oauthParams.getSignatureMethod());
			}
			if (null != oauthParams.getTimestamp()) {
				addToSignificantParameters(significantParameters, OAuthParameter.oauth_timestamp.toString(), oauthParams.getTimestamp());
			}
			if (null != oauthParams.getNonce()) {
				addToSignificantParameters(significantParameters, OAuthParameter.oauth_nonce.toString(), oauthParams.getNonce());
			}
			if (null != oauthParams.getVersion()) {
				addToSignificantParameters(significantParameters, OAuthParameter.oauth_version.toString(), oauthParams.getVersion());
			}
			if (null != oauthParams.getCallback()) {
				addToSignificantParameters(significantParameters, OAuthParameter.oauth_callback.toString(), oauthParams.getCallback());
			}
			if (null != oauthParams.getCallbackConfirmed()) {
				addToSignificantParameters(significantParameters, OAuthParameter.oauth_callback_confirmed.toString(), oauthParams.getCallbackConfirmed());
			}
			if (null != oauthParams.getVerifier()) {
				addToSignificantParameters(significantParameters, OAuthParameter.oauth_verifier.toString(), oauthParams.getVerifier());
			}
		}

		// remove the oauth signature
		significantParameters.remove(OAuthParameter.oauth_signature.toString());
		return significantParameters;
	}

	private void addToSignificantParameters(SortedMap<String, SortedSet<String>> significantParameters, String parameterName, String parameterValue) {
		parameterName = oauthEncode(parameterName);
		parameterValue = oauthEncode(parameterValue);
		SortedSet<String> significantValues = significantParameters.get(parameterName);
		if (significantValues == null) {
			significantValues = new TreeSet<String>();
			significantParameters.put(parameterName, significantValues);
		}
		significantValues.add(parameterValue);
	}

	/**
	 * The configured base URL for this OAuth provider for the given HttpServletRequest. Default implementation return getBaseUrl() + request URI.
	 *
	 * @param request The HttpServletRequest currently processed
	 * @return The configured base URL for this OAuth provider with respect to the supplied HttpServletRequest.
	 */
	protected String getBaseUrl(HttpServletRequest request) {
		String baseUrl = getBaseUrl();
		if (baseUrl != null) {
			StringBuilder builder = new StringBuilder(baseUrl);
			String path = request.getRequestURI();
			if (path != null && !"".equals(path)) {
				if (!baseUrl.endsWith("/") && !path.startsWith("/")) {
					builder.append('/');
				}
				builder.append(path);
			}
			baseUrl = builder.toString();
		}
		return baseUrl;
	}

	/**
	 * The configured base URL for this OAuth provider.
	 *
	 * @return The configured base URL for this OAuth provider.
	 */
	public String getBaseUrl() {
		return baseUrl;
	}

	/**
	 * The configured base URL for the OAuth provider.
	 *
	 * @param baseUrl The configured base URL for the OAuth provider.
	 */
	public void setBaseUrl(String baseUrl) {
		this.baseUrl = baseUrl;
	}
}
