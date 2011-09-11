/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */
package org.apache.shindig.gadgets.oauth2;

import org.apache.shindig.auth.SecurityToken;
import org.apache.shindig.gadgets.GadgetException;
import org.apache.shindig.gadgets.http.HttpFetcher;

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
  private final OAuth2CallbackState callbackState;
  private final HttpFetcher fetcher;

  public OAuth2Accessor(final OAuth2Provider provider, final OAuth2Client client,
      final OAuth2Store store, final SecurityToken securityToken, final HttpFetcher fetcher) {
    this.provider = provider;
    this.client = client;
    this.store = store;
    this.securityToken = securityToken;
    this.callbackState = this.store.createOAuth2CallbackState(this, client, this.flow,
        securityToken, fetcher);
    this.fetcher = fetcher;
  }

  public String getAuthorizationCode() {
    return this.authorizationCode;
  }

  public void setAuthorizationCode(final String authorizationCode) {
    this.authorizationCode = authorizationCode;
  }

  public String getClientId() {
    return this.clientId;
  }

  public void setClientId(final String clientId) {
    this.clientId = clientId;
  }

  public String getRedirectUri() {
    return this.redirectUri;
  }

  public void setRedirectUri(final String redirectUri) {
    this.redirectUri = redirectUri;
  }

  public String getScope() {
    return this.scope;
  }

  public void setScope(final String scope) {
    this.scope = scope;
  }

  public OAuth2Token getAccessToken() {
    if ((this.accessToken == null) && (this.client != null)) {
      try {
        this.accessToken = this.store.getToken(this.client.getProviderName(),
            this.client.getGadgetUri(), this.securityToken.getViewerId(), this.scope,
            OAuth2Token.Type.ACCESS);
      } catch (final GadgetException e) {
        ;
      }
    }
    return this.accessToken;
  }

  public void setAccessToken(final OAuth2Token accessToken) {
    this.accessToken = accessToken;
  }

  public OAuth2Token getRefreshToken() {
    if ((this.refreshToken == null) && (this.client != null)) {
      try {
        this.refreshToken = this.store.getToken(this.client.getProviderName(),
            this.client.getGadgetUri(), this.securityToken.getViewerId(), this.scope,
            OAuth2Token.Type.REFRESH);
      } catch (final GadgetException e) {
        ;
      }
    }
    return this.refreshToken;
  }

  public void setRefreshToken(final OAuth2Token refreshToken) {
    this.refreshToken = refreshToken;
  }

  public String getAuthorizationUrl() {
    return this.authorizationUrl;
  }

  public void setAuthorizationUrl(final String authorizationUrl) {
    this.authorizationUrl = authorizationUrl;
  }

  public String getTokenUrl() {
    return this.tokenUrl;
  }

  public void setTokenUrl(final String tokenUrl) {
    this.tokenUrl = tokenUrl;
  }

  public OAuth2Client.Type getType() {
    return this.type;
  }

  public void setType(final OAuth2Client.Type type) {
    this.type = type;
  }

  public OAuth2Client.Flow getFlow() {
    return this.flow;
  }

  public void setFlow(final OAuth2Client.Flow flow) {
    this.flow = flow;
  }

  public OAuth2Provider getProvider() {
    return this.provider;
  }

  public OAuth2Client getClient() {
    return this.client;
  }

  public OAuth2CallbackState getCallbackState() {
    return this.callbackState;
  }

  public HttpFetcher getFetcher() {
    return this.fetcher;
  }

  public OAuth2Store getStore() {
    return this.store;
  }

  public SecurityToken getSecurityToken() {
    return this.securityToken;
  }

  public String getState() {
    return this.state;
  }
}
