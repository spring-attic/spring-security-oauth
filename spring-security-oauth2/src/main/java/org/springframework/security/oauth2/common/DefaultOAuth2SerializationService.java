package org.springframework.security.oauth2.common;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.util.Date;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.TreeMap;
import java.util.TreeSet;

import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.common.exceptions.RedirectMismatchException;
import org.springframework.security.oauth2.common.exceptions.SerializationException;
import org.springframework.security.oauth2.common.exceptions.UnauthorizedClientException;
import org.springframework.security.oauth2.common.exceptions.UnsupportedGrantTypeException;
import org.springframework.security.oauth2.common.exceptions.UnsupportedResponseTypeException;
import org.springframework.security.oauth2.common.exceptions.UserDeniedAuthorizationException;
import org.springframework.security.oauth2.common.json.JSONException;
import org.springframework.security.oauth2.common.json.JSONObject;
import org.springframework.security.oauth2.common.json.JSONTokener;

/**
 * Default implementation of the OAuth 2 serialization service.
 * 
 * @author Ryan Heaton
 */
public class DefaultOAuth2SerializationService implements OAuth2SerializationService {

	public String serialize(OAuth2AccessToken accessToken) {
		try {
			JSONObject jsonObject = new JSONObject();
			jsonObject.put("access_token", accessToken.getValue());
			jsonObject.put("token_type", accessToken.getTokenType());

			Date expiration = accessToken.getExpiration();
			if (expiration != null) {
				jsonObject.put("expires_in", (expiration.getTime() - System.currentTimeMillis()) / 1000);
			}

			OAuth2RefreshToken refreshToken = accessToken.getRefreshToken();
			if (refreshToken != null) {
				jsonObject.put("refresh_token", refreshToken.getValue());
			}

			Set<String> scope = accessToken.getScope();
			if (scope != null && !scope.isEmpty()) {
				StringBuilder join = new StringBuilder();
				for (String sc : scope) {
					join.append(sc).append(' ');
				}
				jsonObject.put("scope", join.toString().trim());
			}

			return jsonObject.toString(2);
		} catch (JSONException e) {
			throw new SerializationException(e);
		}
	}

	public OAuth2AccessToken deserializeJsonAccessToken(InputStream serialization) {
		try {
			Map<String, String> tokenParams = new TreeMap<String, String>();
			JSONObject object = new JSONObject(new JSONTokener(new InputStreamReader(serialization, "UTF-8")));
			@SuppressWarnings("unchecked")
			Iterator<String> keys = object.keys();
			if (keys != null) {
				while (keys.hasNext()) {
					String key = String.valueOf(keys.next());
					tokenParams.put(key, object.getString(key));
				}
			}

			return deserializeAccessToken(tokenParams);
		} catch (JSONException e) {
			throw new SerializationException(e);
		} catch (UnsupportedEncodingException e) {
			throw new SerializationException(e);
		}
	}

	public OAuth2AccessToken deserializeAccessToken(Map<String, String> tokenParams) {
		OAuth2AccessToken token = new OAuth2AccessToken(tokenParams.get("access_token"));

		if (tokenParams.containsKey("expires_in")) {
			long expiration = 0;
			try {
				expiration = Long.parseLong(tokenParams.get("expires_in"));
			} catch (NumberFormatException e) {
				// fall through...
			}
			token.setExpiration(new Date(System.currentTimeMillis() + (expiration * 1000L)));
		}

		if (tokenParams.containsKey("refresh_token")) {
			String refresh = tokenParams.get("refresh_token");
			OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(refresh);
			token.setRefreshToken(refreshToken);
		}

		if (tokenParams.containsKey("scope")) {
			Set<String> scope = new TreeSet<String>();
			for (StringTokenizer tokenizer = new StringTokenizer(tokenParams.get("scope"), " ,"); tokenizer
					.hasMoreTokens();) {
				scope.add(tokenizer.nextToken());
			}
			token.setScope(scope);
		}

		if (tokenParams.containsKey("token_type")) {
			token.setTokenType(tokenParams.get("token_type"));
		}

		return token;

	}

	public String serialize(OAuth2Exception exception) {
		try {
			JSONObject jsonObject = new JSONObject();
			jsonObject.put("error", exception.getOAuth2ErrorCode());
			jsonObject.put("error_description", exception.getMessage());
			Map<String, String> additionalInfo = exception.getAdditionalInformation();
			if (additionalInfo != null) {
				for (Map.Entry<String, String> entry : additionalInfo.entrySet()) {
					jsonObject.put(entry.getKey(), entry.getValue());
				}
			}
			return jsonObject.toString(2);
		} catch (JSONException e) {
			throw new RuntimeException(e);
		}
	}

	public OAuth2Exception deserializeJsonError(InputStream serialization) {
		try {
			Map<String, String> errorResponse = new TreeMap<String, String>();
			JSONObject object = new JSONObject(new JSONTokener(new InputStreamReader(serialization, "UTF-8")));
			@SuppressWarnings("unchecked")
			Iterator<String> keys = object.keys();
			if (keys != null) {
				while (keys.hasNext()) {
					String key = String.valueOf(keys.next());
					errorResponse.put(key, object.getString(key));
				}
			}

			return deserializeError(errorResponse);
		} catch (JSONException e) {
			throw new SerializationException(e);
		} catch (UnsupportedEncodingException e) {
			throw new SerializationException(e);
		}
	}

	public OAuth2Exception deserializeError(Map<String, String> errorParams) {
		String errorCode = errorParams.get("error");
		String errorMessage = errorParams.containsKey("error_description") ? errorParams.get("error_description")
				: null;
		if (errorMessage == null) {
			errorMessage = errorCode == null ? "OAuth Error" : errorCode;
		}
		OAuth2Exception ex;
		if ("invalid_client".equals(errorCode)) {
			ex = new InvalidClientException(errorMessage);
		} else if ("unauthorized_client".equals(errorCode)) {
			ex = new UnauthorizedClientException(errorMessage);
		} else if ("invalid_grant".equals(errorCode)) {
			ex = new InvalidGrantException(errorMessage);
		} else if ("invalid_scope".equals(errorCode)) {
			ex = new InvalidScopeException(errorMessage);
		} else if ("invalid_token".equals(errorCode)) {
			ex = new InvalidTokenException(errorMessage);
		} else if ("invalid_request".equals(errorCode)) {
			ex = new InvalidRequestException(errorMessage);
		} else if ("redirect_uri_mismatch".equals(errorCode)) {
			ex = new RedirectMismatchException(errorMessage);
		} else if ("unsupported_grant_type".equals(errorCode)) {
			ex = new UnsupportedGrantTypeException(errorMessage);
		} else if ("unsupported_response_type".equals(errorCode)) {
			ex = new UnsupportedResponseTypeException(errorMessage);
		} else if ("access_denied".equals(errorCode)) {
			ex = new UserDeniedAuthorizationException(errorMessage);
		} else {
			ex = new OAuth2Exception(errorMessage);
		}

		Set<Map.Entry<String, String>> entries = errorParams.entrySet();
		for (Map.Entry<String, String> entry : entries) {
			String key = entry.getKey();
			if (!"error".equals(key) && !"error_description".equals(key)) {
				ex.addAdditionalInformation(key, entry.getValue());
			}
		}

		return ex;
	}
}
