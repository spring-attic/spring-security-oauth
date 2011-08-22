/*
 * Copyright 2008 Web Cohesion
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.oauth.provider.filter;

import org.apache.commons.codec.DecoderException;
import static org.springframework.security.oauth.common.OAuthCodec.oauthDecode;
import static org.springframework.security.oauth.common.OAuthCodec.oauthEncode;
import org.springframework.security.oauth.common.OAuthConsumerParameter;
import org.springframework.security.oauth.common.StringSplitUtils;
import org.springframework.security.oauth.provider.OAuthProviderSupport;

import javax.servlet.http.HttpServletRequest;
import java.util.*;
import java.net.URL;
import java.net.MalformedURLException;

/**
 * Utility for common logic for supporting an OAuth provider.
 *
 * @author Ryan Heaton
 */
public class CoreOAuthProviderSupport implements OAuthProviderSupport {

  private final Set<String> supportedOAuthParameters;
  private String baseUrl = null;

  public CoreOAuthProviderSupport() {
    Set<String> supportedOAuthParameters = new TreeSet<String>();
    for (OAuthConsumerParameter supportedParameter : OAuthConsumerParameter.values()) {
      supportedOAuthParameters.add(supportedParameter.toString());
    }
    this.supportedOAuthParameters = supportedOAuthParameters;
  }

  // Inherited.
  public Map<String, String> parseParameters(HttpServletRequest request) {
    Map<String, String> parameters = parseHeaderParameters(request);

    if (parameters == null) {
      //if there is no header authorization parameters, then the oauth parameters are the supported OAuth request parameters.
      parameters = new HashMap<String, String>();
      for (String supportedOAuthParameter : getSupportedOAuthParameters()) {
        String param = request.getParameter(supportedOAuthParameter);
        if (param != null) {
          parameters.put(supportedOAuthParameter, param);
        }
      }
    }

    return parameters;
  }

  /**
   * Parse the OAuth header parameters. The parameters will be oauth-decoded.
   *
   * @param request The request.
   * @return The parsed parameters, or null if no OAuth authorization header was supplied.
   */
  protected Map<String, String> parseHeaderParameters(HttpServletRequest request) {
    String header = null;
    Enumeration<String> headers = request.getHeaders("Authorization");
    while (headers.hasMoreElements()) {
      String value = headers.nextElement();
      if ((value.toLowerCase().startsWith("oauth "))) {
        header = value;
        break;
      }
    }

    Map<String, String> parameters = null;
    if (header != null) {
      parameters = new HashMap<String, String>();
      String authHeaderValue = header.substring(6);

      //create a map of the authorization header values per OAuth Core 1.0, section 5.4.1
      String[] headerEntries = StringSplitUtils.splitIgnoringQuotes(authHeaderValue, ',');
      for (Object o : StringSplitUtils.splitEachArrayElementAndCreateMap(headerEntries, "=", "\"").entrySet()) {
        Map.Entry entry = (Map.Entry) o;
        try {
          String key = oauthDecode((String) entry.getKey());
          String value = oauthDecode((String) entry.getValue());
          parameters.put(key, value);
        }
        catch (DecoderException e) {
          throw new IllegalStateException(e);
        }
      }
    }

    return parameters;
  }

  /**
   * Get the supported OAuth parameters. The default implementation supports only the OAuth core parameters.
   *
   * @return The OAuth core parameters.
   */
  protected Set<String> getSupportedOAuthParameters() {
    return this.supportedOAuthParameters;
  }

  // Inherited.
  public String getSignatureBaseString(HttpServletRequest request) {
    SortedMap<String, SortedSet<String>> significantParameters = loadSignificantParametersForSignatureBaseString(request);

    //now concatenate them into a single query string according to the spec.
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
      //if no URL is configured, then we'll attempt to reconstruct the URL.  This may be inaccurate.
      url = request.getRequestURL().toString();
    }
    url = normalizeUrl(url);
    url = oauthEncode(url);

    String method = request.getMethod().toUpperCase();
    return new StringBuilder(method).append('&').append(url).append('&').append(oauthEncode(queryString.toString())).toString();
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
   * @return The significan parameters.
   */
  protected SortedMap<String, SortedSet<String>> loadSignificantParametersForSignatureBaseString(HttpServletRequest request) {
    //first collect the relevant parameters...
    SortedMap<String, SortedSet<String>> significantParameters = new TreeMap<String, SortedSet<String>>();
    //first pull from the request...
    Enumeration parameterNames = request.getParameterNames();
    while (parameterNames.hasMoreElements()) {
      String parameterName = (String) parameterNames.nextElement();
      String[] values = request.getParameterValues(parameterName);
      if (values == null) {
        values = new String[]{ "" };
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

    //then take into account the header parameter values...
    Map<String, String> oauthParams = parseParameters(request);
    oauthParams.remove("realm"); //remove the realm
    Set<String> parsedParams = oauthParams.keySet();
    for (String parameterName : parsedParams) {
      String parameterValue = oauthParams.get(parameterName);
      if (parameterValue == null) {
        parameterValue = "";
      }

      parameterName = oauthEncode(parameterName);
      parameterValue = oauthEncode(parameterValue);
      SortedSet<String> significantValues = significantParameters.get(parameterName);
      if (significantValues == null) {
        significantValues = new TreeSet<String>();
        significantParameters.put(parameterName, significantValues);
      }
      significantValues.add(parameterValue);
    }

    //remove the oauth signature parameter value.
    significantParameters.remove(OAuthConsumerParameter.oauth_signature.toString());
    return significantParameters;
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
