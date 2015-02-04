/*
 * Copyright 2014 the original author or authors.
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
package org.springframework.security.oauth.common;

import java.io.Serializable;

/**
 * Container for parsed OAuth parameters.
 *
 * @author <a rel="author" href="http://autayeu.com/">Aliaksandr Autayeu</a>
 */
public class OAuthParameters implements Serializable {

    private static final long serialVersionUID = 1L;

	private String consumerKey;
	private String token;
	private String tokenSecret;
	private String signatureMethod;
	private String signature;
	private String timestamp;
	private String nonce;
	private String version;
	private String callback;
	private String callbackConfirmed;
	private String verifier;
	private String realm;

	public String getConsumerKey() {
		return consumerKey;
	}

	public void setConsumerKey(String consumerKey) {
		this.consumerKey = consumerKey;
	}

	public String getToken() {
		return token;
	}

	public void setToken(String token) {
		this.token = token;
	}

	public String getTokenSecret() {
		return tokenSecret;
	}

	public void setTokenSecret(String tokenSecret) {
		this.tokenSecret = tokenSecret;
	}

	public String getSignatureMethod() {
		return signatureMethod;
	}

	public void setSignatureMethod(String signatureMethod) {
		this.signatureMethod = signatureMethod;
	}

	public String getSignature() {
		return signature;
	}

	public void setSignature(String signature) {
		this.signature = signature;
	}

	public String getTimestamp() {
		return timestamp;
	}

	public void setTimestamp(String timestamp) {
		this.timestamp = timestamp;
	}

	public String getNonce() {
		return nonce;
	}

	public void setNonce(String nonce) {
		this.nonce = nonce;
	}

	public String getVersion() {
		return version;
	}

	public void setVersion(String version) {
		this.version = version;
	}

	public String getCallback() {
		return callback;
	}

	public void setCallback(String callback) {
		this.callback = callback;
	}

	public String getCallbackConfirmed() {
		return callbackConfirmed;
	}

	public void setCallbackConfirmed(String callbackConfirmed) {
		this.callbackConfirmed = callbackConfirmed;
	}

	public String getVerifier() {
		return verifier;
	}

	public void setVerifier(String verifier) {
		this.verifier = verifier;
	}

	public String getRealm() {
		return realm;
	}

	public void setRealm(String realm) {
		this.realm = realm;
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		appendParameter(builder, OAuthParameter.oauth_consumer_key.toString(), getConsumerKey());
		appendParameter(builder, OAuthParameter.oauth_token.toString(), getToken());
		appendParameter(builder, OAuthParameter.oauth_token_secret.toString(), getTokenSecret());
		appendParameter(builder, OAuthParameter.oauth_signature_method.toString(), getSignatureMethod());
		appendParameter(builder, OAuthParameter.oauth_signature.toString(), getSignature());
		appendParameter(builder, OAuthParameter.oauth_timestamp.toString(), getTimestamp());
		appendParameter(builder, OAuthParameter.oauth_nonce.toString(), getNonce());
		appendParameter(builder, OAuthParameter.oauth_version.toString(), getVersion());
		appendParameter(builder, OAuthParameter.oauth_callback.toString(), getCallback());
		appendParameter(builder, OAuthParameter.oauth_callback_confirmed.toString(), getCallbackConfirmed());
		appendParameter(builder, OAuthParameter.oauth_verifier.toString(), getVerifier());
		return builder.toString();
	}

	private void appendParameter(StringBuilder builder, String name, String value) {
		if (null != value) {
			builder.append(name).append("=").append(value).append(" ");
		}
	}
}