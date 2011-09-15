/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.apache.shindig.social.core.oauth2;

import java.util.HashMap;
import java.util.Map;

/**
 * Wraps OAuth 2.0 response elements including headers and body parameters.
 * 
 * TODO: document this class, including bodyReturned
 */
public class OAuth2NormalizedResponse {
	
	private Map<String, String> headers;
	private Map<String, String> respParams;
	private int status;
	private boolean bodyReturned;

	public OAuth2NormalizedResponse() {
		this.headers = new HashMap<String, String>();
		this.respParams = new HashMap<String, String>();
		this.status = -1;
		this.bodyReturned = false;
	}
	
	public void setStatus(int status) {
	  this.status = status;
	}
	
	public int getStatus() {
	  return status;
	}
	
	public void setBodyReturned(boolean bodyReturned) {
	  this.bodyReturned = bodyReturned;
	}
	
	public boolean isBodyReturned() {
	  return bodyReturned;
	}
	
  // ------------------------------- HEADER FIELDS ----------------------------
	public Map<String, String> getHeaders() {
		return headers;
	}
	
	public void setHeaders(Map<String, String> headers) {
		this.headers = headers;
	}
	
  public void setHeader(String key, String value) {
    headers.put(key, value);
  }
	
	// ------------------------------ RESPONSE FIELDS ---------------------------
  public Map<String, String> getResponseParameters() {
    return respParams;
  }
  
  public void setResponseParameters(Map<String, String> responseParams) {
    this.respParams = responseParams;
  }
  
	public void setError(String error) {
	  respParams.put("error", error);
	}
	
	public String getError() {
		return respParams.get("error");
	}
	
	public void setErrorDescription(String errorDescription) {
	  respParams.put("error_description", errorDescription);
	}
	
	public String getErrorDescription() {
		return respParams.get("error_description");
	}
	
	public void setErrorUri(String errorUri) {
	  respParams.put("error_uri", errorUri);
	}
	
	public String getErrorUri() {
		return respParams.get("error_uri");
	}
	
	public void setState(String state) {
	  respParams.put("state", state);
	}
	
	public String getState() {
		return respParams.get("state");
	}
	
	public void setCode(String code) {
	  respParams.put("code", code);
	}
	
	public String getCode() {
		return respParams.get("code");
	}
	
	public void setAccessToken(String accessToken) {
	  respParams.put("access_token", accessToken);
	}
	
	public String getAccessToken() {
		return respParams.get("access_token");
	}
	
	public void setTokenType(String tokenType) {
	  respParams.put("token_type", tokenType);
	}
	
	public String getTokenType() {
		return respParams.get("token_type");
	}
	
	public void setExpiresIn(String expiresIn) {
	  respParams.put("expires_in", expiresIn);
	}
	
	public String getExpiresIn() {
		return respParams.get("expires_in");
	}
	
	public void setRefreshToken(String refreshToken) {
	  respParams.put("refresh_token", refreshToken);
	}
	
	public String getRefreshToken() {
		return respParams.get("refresh_token");
	}
	
	public void setScope(String scope) {
	  respParams.put("scope", scope);
	}
	
	public String getScope() {
		return respParams.get("scope");
	}
}
