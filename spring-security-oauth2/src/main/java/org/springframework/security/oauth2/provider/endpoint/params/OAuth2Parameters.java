package org.springframework.security.oauth2.provider.endpoint.params;

import java.util.HashMap;
import java.util.Map;

public class OAuth2Parameters {

	private String grantType = "authorization_code";
	private String clientId;
	private String clientSecret;
	private String username;
	private String password;
	private String scope;
	private String refreshToken;

	private Map<String, String> _params = new HashMap<String, String>();

	public Map<String, String> getParameters(){
		return _params;
	}

	public String getClientId() {
		return clientId;
	}

	public void setClientId(String clientId) {
		this.clientId = clientId;
		_params.put("client_id", clientId);
	}

	public String getClientSecret() {
		return clientSecret;
	}

	public void setClientSecret(String clientSecret) {
		this.clientSecret = clientSecret;
		_params.put("client_secret", clientSecret);
	}

	public String getGrantType() {
		return grantType;
	}

	public void setGrantType(String grantType) {
		this.grantType = grantType;
		_params.put("grant_type", grantType);
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
		_params.put("password", password);
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
		_params.put("username", username);
	}

	public String getScope() {
		return scope;
	}

	public void setScope(String scope) {
		this.scope = scope;
		_params.put("scope", scope);
	}

	public String getRefreshToken() {
		return refreshToken;
	}

	public void setRefreshToken(String refreshToken) {
		this.refreshToken = refreshToken;
		_params.put("refresh_token", refreshToken);
	}

	@Override
	public String toString() {
		final StringBuilder sb = new StringBuilder();
		sb.append("OAuth2Parameters");
		sb.append("{_params=").append(_params);
		sb.append('}');
		return sb.toString();
	}
}
