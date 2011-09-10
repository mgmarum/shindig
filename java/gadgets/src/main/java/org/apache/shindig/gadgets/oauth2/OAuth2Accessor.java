/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */
package org.apache.shindig.gadgets.oauth2;

import org.apache.shindig.auth.SecurityToken;

/**
 * OAuth2 related data accessor
 */

// NO IBM CONFIDENTIAL CODE OR INFORMATION!

public class OAuth2Accessor {
  private final OAuth2Provider provider;
  private final OAuth2Client client;
  private final OAuth2Store store;
  private final SecurityToken securityToken;

  
  
  private String authorizationCode;
  private String clientId;
  private String redirectUri;
  private String scope;
  private String state;
  private OAuth2Token accessToken;
  private OAuth2Token refreshToken;
  private String authorizationUrl;
  private String tokenUrl;
  private OAuth2Client.Type type;
  private OAuth2Client.Flow flow;

  public OAuth2Accessor(final OAuth2Provider provider, final OAuth2Client client, final OAuth2Store store, final SecurityToken securityToken) {
    this.provider = provider;
    this.client = client;
    this.store = store;
    this.securityToken = securityToken;
  }

  public String getAuthorizationCode() {
    return authorizationCode;
  }

  public void setAuthorizationCode(String authorizationCode) {
    this.authorizationCode = authorizationCode;
  }

  public String getClientId() {
    return clientId;
  }

  public void setClientId(String clientId) {
    this.clientId = clientId;
  }

  public String getRedirectUri() {
    return redirectUri;
  }

  public void setRedirectUri(String redirectUri) {
    this.redirectUri = redirectUri;
  }

  public String getScope() {
    return scope;
  }

  public void setScope(String scope) {
    this.scope = scope;
  }

  public OAuth2Token getAccessToken() {
    return accessToken;
  }

  public void setAccessToken(OAuth2Token accessToken) {
    this.accessToken = accessToken;
  }

  public OAuth2Token getRefreshToken() {
    return refreshToken;
  }

  public void setRefreshToken(OAuth2Token refreshToken) {
    this.refreshToken = refreshToken;
  }

  public String getAuthorizationUrl() {
    return authorizationUrl;
  }

  public void setAuthorizationUrl(String authorizationUrl) {
    this.authorizationUrl = authorizationUrl;
  }

  public String getTokenUrl() {
    return tokenUrl;
  }

  public void setTokenUrl(String tokenUrl) {
    this.tokenUrl = tokenUrl;
  }

  public OAuth2Client.Type getType() {
    return type;
  }

  public void setType(OAuth2Client.Type type) {
    this.type = type;
  }

  public OAuth2Client.Flow getFlow() {
    return flow;
  }

  public void setFlow(OAuth2Client.Flow flow) {
    this.flow = flow;
  }

  public OAuth2Provider getProvider() {
    return provider;
  }

  public OAuth2Client getClient() {
    return client;
  }
  
  public OAuth2CallbackState getCallbackState() {
    return this.store.createOAuth2CallbackState(flow, securityToken, securityToken.getAppUrl(), securityToken.getAppUrl());
  }
}
