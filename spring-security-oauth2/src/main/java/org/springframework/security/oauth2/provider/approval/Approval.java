/*
 * Copyright 2012-2013 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.oauth2.provider.approval;

import java.util.Calendar;
import java.util.Date;

import org.codehaus.jackson.annotate.JsonIgnore;
import org.codehaus.jackson.map.annotate.JsonDeserialize;
import org.codehaus.jackson.map.annotate.JsonSerialize;
import org.springframework.security.oauth2.common.util.JsonDateDeserializer;
import org.springframework.security.oauth2.common.util.JsonDateSerializer;

/**
 * @author Dave Syer
 * @author Vidya Val
 *
 */
@JsonSerialize(include = JsonSerialize.Inclusion.NON_NULL)
public class Approval {

	private String userId;

	private String clientId;

	private String scope;

	public enum ApprovalStatus {
		APPROVED,
		DENIED;
	}

	private ApprovalStatus status;
	
	private Date expiresAt;

	private Date lastUpdatedAt;

	public Approval(String userId, String clientId, String scope, int expiresIn, ApprovalStatus status) {
		this(userId, clientId, scope, new Date(), status, new Date());
		Calendar expiresAt = Calendar.getInstance();
		expiresAt.add(Calendar.MILLISECOND, expiresIn);
		setExpiresAt(expiresAt.getTime());
	}

	public Approval(String userId, String clientId, String scope, Date expiresAt, ApprovalStatus status) {
		this(userId, clientId, scope, expiresAt, status, new Date());
	}

	public Approval(String userId, String clientId, String scope, Date expiresAt, ApprovalStatus status, Date lastUpdatedAt) {
		this.userId = userId;
		this.clientId = clientId;
		this.scope = scope;
		this.expiresAt = expiresAt;
		this.status = status;
		this.lastUpdatedAt = lastUpdatedAt;
	}

	protected Approval() { }

	public String getUserId() {
		return userId;
	}

	public void setUserId(String userId) {
		this.userId = userId == null ? "" : userId;
	}

	public String getClientId() {
		return clientId;
	}

	public void setClientId(String clientId) {
		this.clientId = clientId == null ? "" : clientId;
	}

	public String getScope() {
		return scope;
	}

	public void setScope(String scope) {
		this.scope = scope == null ? "" : scope;
	}

	@JsonSerialize(using = JsonDateSerializer.class, include = JsonSerialize.Inclusion.NON_NULL)
	public Date getExpiresAt() {
		return expiresAt;
	}

	@JsonDeserialize(using = JsonDateDeserializer.class)
	public void setExpiresAt(Date expiresAt) {
		if (expiresAt == null) {
			Calendar thirtyMinFromNow = Calendar.getInstance();
			thirtyMinFromNow.add(Calendar.MINUTE, 30);
			expiresAt = thirtyMinFromNow.getTime();
		}
		this.expiresAt = expiresAt;
	}

	@JsonSerialize(using = JsonDateSerializer.class, include = JsonSerialize.Inclusion.NON_NULL)
	public Date getLastUpdatedAt() {
		return lastUpdatedAt;
	}

	@JsonDeserialize(using = JsonDateDeserializer.class)
	public void setLastUpdatedAt(Date lastUpdatedAt) {
		this.lastUpdatedAt = lastUpdatedAt;
	}

	@JsonIgnore
	public boolean isCurrentlyActive() {
		return expiresAt != null && expiresAt.after(new Date());
	}

	@JsonIgnore
	public boolean isApproved() {
		return isCurrentlyActive() && status==ApprovalStatus.APPROVED;
	}

	public void setStatus(ApprovalStatus status) {
		this.status = status;
	}

	public ApprovalStatus getStatus() {
		return status;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + userId.hashCode();
		result = prime * result + clientId.hashCode();
		result = prime * result + scope.hashCode();
		result = prime * result + status.hashCode();
		return result;
	}

	@Override
	public boolean equals(Object o) {
		if (o == null || !(o instanceof Approval)) {
			return false;
		}
		Approval other = (Approval) o;
		return userId.equals(other.userId) && clientId.equals(other.clientId) && scope.equals(other.scope) && status == other.status;
	}

	@Override
	public String toString() {
		return String.format("[%s, %s, %s, %s, %s, %s]", userId, scope, clientId, expiresAt, status.toString(), lastUpdatedAt);
	}

}
