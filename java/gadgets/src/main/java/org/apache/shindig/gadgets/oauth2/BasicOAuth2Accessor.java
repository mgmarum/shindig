/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with this
 * work for additional information regarding copyright ownership. The ASF
 * licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.apache.shindig.gadgets.oauth2;

// Probably no need to ever changes this.  Think about removing inteface.
/**
 * 
 * see {@link OAuth2Accessor}
 */
public class BasicOAuth2Accessor implements OAuth2Accessor {
  private static final long serialVersionUID = 1L;
  private OAuth2Token accessToken;
  private final boolean allowModuleOverrides;
  private String authorizationUrl;
  private String clientAuthenticationType;
  private String clientId;
  private String clientSecret;
  private final String gadgetUri;
  private String grantType;
  private String redirectUri;
  private OAuth2Token refreshToken;
  private final String scope;
  private final String serviceName;
  private final String state;
  private String tokenUrl;
  private Type type;
  private final String user;
  private final String globalRedirectUri;

  public BasicOAuth2Accessor(final String gadgetUri, final String serviceName, final String user,
      final String scope, final boolean allowModuleOverrides, final OAuth2Store store,
      final String globalRedirectUri) {
    this.gadgetUri = gadgetUri;
    this.serviceName = serviceName;
    this.user = user;
    this.scope = scope;
    this.allowModuleOverrides = allowModuleOverrides;
    this.globalRedirectUri = globalRedirectUri;
    this.state = store.getOAuth2AccessorIndex(gadgetUri, serviceName, user, scope).toString();
  }

  public BasicOAuth2Accessor(final OAuth2Accessor accessor) {
    this.accessToken = accessor.getAccessToken();
    this.authorizationUrl = accessor.getAuthorizationUrl();
    this.clientAuthenticationType = accessor.getClientAuthenticationType();
    this.clientId = accessor.getClientId();
    this.clientSecret = accessor.getClientSecret();
    this.gadgetUri = accessor.getGadgetUri();
    this.grantType = accessor.getGrantType();
    this.redirectUri = accessor.getRedirectUri();
    this.refreshToken = accessor.getRefreshToken();
    this.serviceName = accessor.getServiceName();
    this.scope = accessor.getScope();
    this.state = accessor.getState();
    this.tokenUrl = accessor.getTokenUrl();
    this.type = accessor.getType();
    this.user = accessor.getUser();
    this.allowModuleOverrides = false;
    this.globalRedirectUri = null;
  }

  public OAuth2Token getAccessToken() {
    return this.accessToken;
  }

  public void setAccessToken(final OAuth2Token accessToken) {
    this.accessToken = accessToken;
  }

  public String getAuthorizationUrl() {
    return this.authorizationUrl;
  }

  public void setAuthorizationUrl(final String authorizationUrl) {
    this.authorizationUrl = authorizationUrl;
  }

  public String getClientAuthenticationType() {
    return this.clientAuthenticationType;
  }

  public void setClientAuthenticationType(final String clientAuthenticationType) {
    this.clientAuthenticationType = clientAuthenticationType;
  }

  public String getClientId() {
    return this.clientId;
  }

  public void setClientId(final String clientId) {
    this.clientId = clientId;
  }

  public String getClientSecret() {
    return this.clientSecret;
  }

  public void setClientSecret(final String clientSecret) {
    this.clientSecret = clientSecret;
  }

  public String getGadgetUri() {
    return this.gadgetUri;
  }

  public String getGrantType() {
    return this.grantType;
  }

  public void setGrantType(final String grantType) {
    this.grantType = grantType;
  }

  public String getRedirectUri() {
    if ((this.redirectUri == null) || (this.redirectUri.length() == 0)) {
      return this.globalRedirectUri;
    }
    return this.redirectUri;
  }

  public void setRedirectUri(final String redirectUri) {
    this.redirectUri = redirectUri;
  }

  public OAuth2Token getRefreshToken() {
    return this.refreshToken;
  }

  public void setRefreshToken(final OAuth2Token refreshToken) {
    this.refreshToken = refreshToken;
  }

  public String getScope() {
    return this.scope;
  }

  public String getServiceName() {
    return this.serviceName;
  }

  public String getState() {
    return this.state;
  }

  public String getTokenUrl() {
    return this.tokenUrl;
  }

  public void setTokenUrl(final String tokenUrl) {
    this.tokenUrl = tokenUrl;
  }

  public Type getType() {
    return this.type;
  }

  public void setType(final Type type) {
    this.type = type;
  }

  public String getUser() {
    return this.user;
  }

  public boolean isAllowModuleOverrides() {
    return this.allowModuleOverrides;
  }
}
