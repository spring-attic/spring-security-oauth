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

package org.springframework.security.oauth.consumer;

import java.util.Map;

import org.springframework.security.oauth.common.signature.HMAC_SHA1SignatureMethod;
import org.springframework.security.oauth.common.signature.SignatureSecret;

/**
 * Basic implementation of protected resource details.
 *
 * @author Ryan Heaton
 */
public class BaseProtectedResourceDetails implements ProtectedResourceDetails {

  private String id;
  private String consumerKey;
	private String signatureMethod = HMAC_SHA1SignatureMethod.SIGNATURE_NAME;
  private SignatureSecret sharedSecret;
  private String requestTokenURL;
  private String requestTokenHttpMethod = "POST";
  private String userAuthorizationURL;
  private String accessTokenURL;
  private String accessTokenHttpMethod = "POST";
  private boolean acceptsAuthorizationHeader = true;
  private String authorizationHeaderRealm;
  private boolean use10a = true;
  private Map<String, String> additionalParameters;
  private Map<String, String> additionalRequestHeaders;

  public String getId() {
    return id;
  }

  public void setId(String id) {
    this.id = id;
  }

  public String getConsumerKey() {
    return consumerKey;
  }

  public void setConsumerKey(String consumerKey) {
    this.consumerKey = consumerKey;
  }

  public String getSignatureMethod() {
    return signatureMethod;
  }

  public void setSignatureMethod(String signatureMethod) {
    this.signatureMethod = signatureMethod;
  }

  public SignatureSecret getSharedSecret() {
    return sharedSecret;
  }

  public void setSharedSecret(SignatureSecret sharedSecret) {
    this.sharedSecret = sharedSecret;
  }

  public String getRequestTokenURL() {
    return requestTokenURL;
  }

  public void setRequestTokenURL(String requestTokenURL) {
    this.requestTokenURL = requestTokenURL;
  }

  public String getRequestTokenHttpMethod() {
    return requestTokenHttpMethod;
  }

  public void setRequestTokenHttpMethod(String requestTokenHttpMethod) {
    this.requestTokenHttpMethod = requestTokenHttpMethod;
  }

  public String getUserAuthorizationURL() {
    return userAuthorizationURL;
  }

  public void setUserAuthorizationURL(String userAuthorizationURL) {
    this.userAuthorizationURL = userAuthorizationURL;
  }

  public String getAccessTokenURL() {
    return accessTokenURL;
  }

  public void setAccessTokenURL(String accessTokenURL) {
    this.accessTokenURL = accessTokenURL;
  }

  public String getAccessTokenHttpMethod() {
    return accessTokenHttpMethod;
  }

  public void setAccessTokenHttpMethod(String accessTokenHttpMethod) {
    this.accessTokenHttpMethod = accessTokenHttpMethod;
  }

  public boolean isAcceptsAuthorizationHeader() {
    return acceptsAuthorizationHeader;
  }

  public void setAcceptsAuthorizationHeader(boolean acceptsAuthorizationHeader) {
    this.acceptsAuthorizationHeader = acceptsAuthorizationHeader;
  }

  public String getAuthorizationHeaderRealm() {
    return authorizationHeaderRealm;
  }

  public void setAuthorizationHeaderRealm(String authorizationHeaderRealm) {
    this.authorizationHeaderRealm = authorizationHeaderRealm;
  }

  public boolean isUse10a() {
    return use10a;
  }

  public void setUse10a(boolean use10a) {
    this.use10a = use10a;
  }

  public Map<String, String> getAdditionalParameters() {
    return additionalParameters;
  }

  public void setAdditionalParameters(Map<String, String> additionalParameters) {
    this.additionalParameters = additionalParameters;
  }

  public Map<String, String> getAdditionalRequestHeaders() {
    return additionalRequestHeaders;
  }

  public void setAdditionalRequestHeaders(Map<String, String> additionalRequestHeaders) {
    this.additionalRequestHeaders = additionalRequestHeaders;
  }
}
