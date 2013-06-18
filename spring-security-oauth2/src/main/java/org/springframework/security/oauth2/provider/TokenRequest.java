package org.springframework.security.oauth2.provider;

import java.util.Map;
import java.util.Set;

public class TokenRequest {

	private Map<String, String> requestParameters;
	private String clientId;
	private Set<String> scope;
	private String grantType;
	
	public TokenRequest(Map<String, String> requestParameters, String clientId, Set<String> scope) {
		this.requestParameters = requestParameters;
		this.clientId = clientId;
		this.scope = scope;
	}

	public Map<String, String> getRequestParameters() {
		return requestParameters;
	}

	public void setRequestParameters(Map<String, String> requestParameters) {
		this.requestParameters = requestParameters;
	}

	public String getClientId() {
		return clientId;
	}

	public void setClientId(String clientId) {
		this.clientId = clientId;
	}

	public Set<String> getScope() {
		return scope;
	}

	public void setScope(Set<String> scope) {
		this.scope = scope;
	}
	
}
