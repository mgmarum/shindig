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

import java.util.List;

import org.apache.shindig.social.core.oauth2.OAuth2Types.CodeType;

/**
 * Represents a "code" string in an OAuth 2.0 handshake, including
 * authorization code, access token, or refresh token.  These signatures may
 * all expire.  They may also be associated with a redirect_url and/or another
 * code.
 */
public class OAuth2Code implements Comparable<OAuth2Code> {
  
  private String value;
  private String redirectURI;
  private long expiration;
  private List<String> scope; // TODO: simply a string, interpret as a list during validation
  private OAuth2Client client;
  private OAuth2Code relatedAuthCode;
  private OAuth2Code relatedRefreshToken;
  private OAuth2Code relatedAccessToken;
  private CodeType type;
  
  public OAuth2Code() {
    
  }
    
  public OAuth2Code(String value, String redirectURI, long expiration, List<String> scope) {
    this.value = value;
    this.redirectURI = redirectURI;
    this.expiration = expiration;
    this.scope = scope;
  }
  
  public OAuth2Code(String value) {
    this.value = value;
  }

  public String getValue() { 
    return value;
  }
  
  public void setValue(String value) {
    this.value = value;
  }
  
  public String getRedirectURI() {
    return redirectURI;
  }
  
  public void setRedirectURI(String redirectURI) {
    this.redirectURI = redirectURI;
  }
  
  public long getExpiration() {
    return expiration;
  }
  
  public void setExpiration(long expiration) {
    this.expiration = expiration;
  }

  public int compareTo(OAuth2Code target) {
    return value.compareTo(target.getValue());
  }
  
  public List<String> getScope() {
    return scope;
  }
  
  public void setScope(List<String> scope) {
    this.scope = scope;
  }

  public void setClient(OAuth2Client client) {
    this.client = client;
  }

  public OAuth2Client getClient() {
    return client;
  }
  
  public void setType(CodeType type) {
    this.type = type;
  }
  
  public CodeType getType() {
    return type;
  }
  
  public void setRelatedAuthCode(OAuth2Code code) {
    this.relatedAuthCode = code;
  }
  
  public OAuth2Code getRelatedAuthCode() {
    return relatedAuthCode;
  }

  public void setRelatedRefreshToken(OAuth2Code relatedRefreshToken) {
    this.relatedRefreshToken = relatedRefreshToken;
  }

  public OAuth2Code getRelatedRefreshToken() {
    return relatedRefreshToken;
  }

  public void setRelatedAccessToken(OAuth2Code relatedAccessToken) {
    this.relatedAccessToken = relatedAccessToken;
  }

  public OAuth2Code getRelatedAccessToken() {
    return relatedAccessToken;
  }
}
