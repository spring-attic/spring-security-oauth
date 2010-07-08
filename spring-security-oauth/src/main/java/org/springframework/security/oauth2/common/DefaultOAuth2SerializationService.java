package org.springframework.security.oauth2.common;

import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.common.exceptions.SerializationException;
import org.springframework.security.oauth2.common.json.JSONException;
import org.springframework.security.oauth2.common.json.JSONObject;

import java.util.*;

/**
 * Default implementation of the OAuth 2 serialization service.
 *
 * @author Ryan Heaton
 */
public class DefaultOAuth2SerializationService implements OAuth2SerializationService {

  public OAuth2Serialization serialize(OAuth2AccessToken accessToken, String serializationType) {
    if ("xml".equalsIgnoreCase(serializationType)) {
      //todo: support xml
      throw new UnsupportedOperationException();
    }
    else if ("form".equalsIgnoreCase(serializationType)) {
      //todo: support form
      throw new UnsupportedOperationException();
    }
    else {
      //default is json per the spec.
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

        String secret = accessToken.getSecret();
        if (secret != null) {
          jsonObject.put("access_token_secret", secret);
        }

        Set<String> scope = accessToken.getScope();
        if (scope != null && !scope.isEmpty()) {
          StringBuilder join = new StringBuilder();
          for (String sc : scope) {
            join.append(sc).append(' ');
          }
          jsonObject.put("scope", join.toString().trim());
        }

        return new OAuth2Serialization("application/json", jsonObject.toString(2));
      }
      catch (JSONException e) {
        throw new SerializationException(e);
      }
    }
  }

  public OAuth2AccessToken deserializeAccessToken(OAuth2Serialization serialization) {
    String mediaType = serialization.getMediaType();
    if ("application/xml".equalsIgnoreCase(mediaType) || "text/xml".equalsIgnoreCase(mediaType)) {
      //todo: support xml
      throw new UnsupportedOperationException();
    }
    else if ("application/x-www-form-urlencoded".equalsIgnoreCase(mediaType)) {
      //todo: support form
      throw new UnsupportedOperationException();
    }
    else {
      try {
        JSONObject object = new JSONObject(serialization.getSerializedForm());
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

        if (object.has("access_token_secret")) {
          token.setSecret(object.getString("access_token_secret"));
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
  }

  public OAuth2Serialization serialize(OAuth2Exception exception, String serializationType) {
    if ("xml".equalsIgnoreCase(serializationType)) {
      //todo: support xml
      throw new UnsupportedOperationException();
    }
    else if ("form".equalsIgnoreCase(serializationType)) {
      //todo: support form
      throw new UnsupportedOperationException();
    }
    else {
      try {
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("error", exception.getOAuth2ErrorCode());
        Map<String,String> additionalInfo = exception.getAdditionalInformation();
        if (additionalInfo != null) {
          for (Map.Entry<String, String> entry : additionalInfo.entrySet()) {
            jsonObject.put(entry.getKey(), entry.getValue());
          }
        }
        return new OAuth2Serialization("application/json", jsonObject.toString(2));
      }
      catch (JSONException e) {
        throw new RuntimeException(e);
      }
    }
  }

  public OAuth2Exception deserializeError(OAuth2Serialization serialization) {
    //todo: fill in error handing.
    return new OAuth2Exception("error");
  }
}
