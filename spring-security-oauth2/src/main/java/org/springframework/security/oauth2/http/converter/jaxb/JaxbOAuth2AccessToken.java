/*
 * Copyright 2011 the original author or authors.
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
package org.springframework.security.oauth2.http.converter.jaxb;

import java.util.Date;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlTransient;

@XmlRootElement(name = "oauth")
class JaxbOAuth2AccessToken {
	private String accessToken;

	private Long expiresIn;

	private String refreshToken;

	@XmlElement(name = "access_token")
	public String getAccessToken() {
		return accessToken;
	}

	public void setAccessToken(String accessToken) {
		this.accessToken = accessToken;
	}

	@XmlElement(name = "expires_in")
	public Long getExpiresIn() {
		return expiresIn;
	}

	public void setExpiresIn(Long expiresIn) {
		this.expiresIn = expiresIn;
	}

	public void setExpriation(Date expiration) {
		if(expiration == null) {
			setExpiresIn(null);
			return;
		}
		long now = System.currentTimeMillis();
		setExpiresIn((expiration.getTime() - now) / 1000);
	}

	@XmlTransient
	public Date getExpiration() {
		if(expiresIn == null) {
			return null;
		}
		long now = System.currentTimeMillis();
		return new Date(now + (expiresIn * 1000));
	}

	@XmlElement(name = "refresh_token")
	public String getRefreshToken() {
		return refreshToken;
	}

	public void setRefreshToken(String refreshToken) {
		this.refreshToken = refreshToken;
	}

}
