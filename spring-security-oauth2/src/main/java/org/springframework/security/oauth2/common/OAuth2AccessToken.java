/*
 * Copyright 2006-2011 the original author or authors.
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
package org.springframework.security.oauth2.common;

import java.util.Date;
import java.util.Map;
import java.util.Set;

/**
 * @author Dave Syer
 *
 */
@org.codehaus.jackson.map.annotate.JsonSerialize(using = OAuth2AccessTokenJackson1Serializer.class)
@org.codehaus.jackson.map.annotate.JsonDeserialize(using = OAuth2AccessTokenJackson1Deserializer.class)
@com.fasterxml.jackson.databind.annotation.JsonSerialize(using = OAuth2AccessTokenJackson2Serializer.class)
@com.fasterxml.jackson.databind.annotation.JsonDeserialize(using = OAuth2AccessTokenJackson2Deserializer.class)

public interface OAuth2AccessToken {

	public static String BEARER_TYPE = "Bearer";

	public static String OAUTH2_TYPE = "OAuth2";

	/**
	 * The access token issued by the authorization server. This value is REQUIRED.
	 */
	public static String ACCESS_TOKEN = "access_token";

	/**
	 * The type of the token issued as described in <a
	 * href="http://tools.ietf.org/html/draft-ietf-oauth-v2-22#section-7.1">Section 7.1</a>. Value is case insensitive.
	 * This value is REQUIRED.
	 */
	public static String TOKEN_TYPE = "token_type";

	/**
	 * The lifetime in seconds of the access token. For example, the value "3600" denotes that the access token will
	 * expire in one hour from the time the response was generated. This value is OPTIONAL.
	 */
	public static String EXPIRES_IN = "expires_in";

	/**
	 * The refresh token which can be used to obtain new access tokens using the same authorization grant as described
	 * in <a href="http://tools.ietf.org/html/draft-ietf-oauth-v2-22#section-6">Section 6</a>. This value is OPTIONAL.
	 */
	public static String REFRESH_TOKEN = "refresh_token";

	/**
	 * The scope of the access token as described by <a
	 * href="http://tools.ietf.org/html/draft-ietf-oauth-v2-22#section-3.3">Section 3.3</a>
	 */
	public static String SCOPE = "scope";

	/**
	 * The additionalInformation map is used by the token serializers to export any fields used by extensions of OAuth.
	 * @return a map from the field name in the serialized token to the value to be exported. The default serializers 
	 * make use of Jackson's automatic JSON mapping for Java objects (for the Token Endpoint flows) or implicitly call 
	 * .toString() on the "value" object (for the implicit flow) as part of the serialization process.
	 */
	Map<String, Object> getAdditionalInformation();

	Set<String> getScope();

	OAuth2RefreshToken getRefreshToken();

	String getTokenType();

	boolean isExpired();

	Date getExpiration();

	int getExpiresIn();

	String getValue();

}
