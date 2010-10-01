package org.springframework.security.oauth2.common;

import org.springframework.security.oauth2.common.exceptions.*;
import org.springframework.security.oauth2.common.json.JSONException;
import org.springframework.security.oauth2.common.json.JSONObject;
import org.springframework.security.oauth2.common.json.JSONTokener;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.util.*;

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
    }
    catch (JSONException e) {
      throw new SerializationException(e);
    }
  }

  public OAuth2AccessToken deserializeAccessToken(String serialization) {
    try {
      JSONObject object = new JSONObject(serialization);
      OAuth2AccessToken token = new OAuth2AccessToken();
      token.setValue(object.getString("access_token"));

      if (object.has("expires_in")) {
        long expiration = object.getLong("expires_in");
        token.setExpiration(new Date(expiration * 1000));
      }

      if (object.has("refresh_token")) {
        String refresh = object.getString("refresh_token");
        OAuth2RefreshToken refreshToken = new OAuth2RefreshToken();
        refreshToken.setValue(refresh);
        token.setRefreshToken(refreshToken);
      }

      if (object.has("scope")) {
        Set<String> scope = new TreeSet<String>();
        for (StringTokenizer tokenizer = new StringTokenizer(object.getString("scope"), " ,"); tokenizer.hasMoreTokens();) {
          scope.add(tokenizer.nextToken());
        }
        token.setScope(scope);
      }
      return token;
    }
    catch (JSONException e) {
      throw new SerializationException(e);
    }
  }

  public String serialize(OAuth2Exception exception) {
    try {
      JSONObject jsonObject = new JSONObject();
      jsonObject.put("error", exception.getOAuth2ErrorCode());
      jsonObject.put("error_description", exception.getMessage());
      Map<String,String> additionalInfo = exception.getAdditionalInformation();
      if (additionalInfo != null) {
        for (Map.Entry<String, String> entry : additionalInfo.entrySet()) {
          jsonObject.put(entry.getKey(), entry.getValue());
        }
      }
      return jsonObject.toString(2);
    }
    catch (JSONException e) {
      throw new RuntimeException(e);
    }
  }

  public OAuth2Exception deserializeJsonError(InputStream serialization) {
    try {
      Map<String, String> errorResponse = new TreeMap<String, String>();
      JSONObject object = new JSONObject(new JSONTokener(new InputStreamReader(serialization, "UTF-8")));
      Iterator keys = object.keys();
      if (keys != null) {
        while (keys.hasNext()) {
          String key = String.valueOf(keys.next());
          errorResponse.put(key, object.getString(key));
        }
      }

      return deserializeError(errorResponse);
    }
    catch (JSONException e) {
      throw new SerializationException(e);
    }
    catch (UnsupportedEncodingException e) {
      throw new SerializationException(e);
    }
  }

  public OAuth2Exception deserializeError(Map<String, String> errorParams) {
    String errorCode = errorParams.get("error");
    String errorMessage = errorParams.containsKey("error_description") ? errorParams.get("error_description") : null;
    if (errorMessage == null) {
      errorMessage = errorCode == null ? "OAuth Error" : errorCode;
    }
    OAuth2Exception ex;
    if ("expired_token".equals(errorCode)) {
      ex = new ExpiredTokenException(errorMessage);
    }
    else if ("invalid_client".equals(errorCode)) {
      ex = new InvalidClientException(errorMessage);
    }
    else if ("unauthorized_client".equals(errorCode)) {
      ex = new UnauthorizedClientException(errorMessage);
    }
    else if ("invalid_grant".equals(errorCode)) {
      ex = new InvalidGrantException(errorMessage);
    }
    else if ("invalid_scope".equals(errorCode)) {
      ex = new InvalidScopeException(errorMessage);
    }
    else if ("invalid_token".equals(errorCode)) {
      ex = new InvalidTokenException(errorMessage);
    }
    else if ("redirect_uri_mismatch".equals(errorCode)) {
      ex = new RedirectMismatchException(errorMessage);
    }
    else if ("unsupported_grant_type".equals(errorCode)) {
      ex = new UnsupportedGrantTypeException(errorMessage);
    }
    else if ("unsupported_response_type".equals(errorCode)) {
      ex = new UnsupportedResponseTypeException(errorMessage);
    }
    else if ("access_denied".equals(errorCode)) {
      ex = new UserDeniedVerificationException(errorMessage);
    }
    else {
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
