/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */
package org.apache.shindig.gadgets.oauth2;

/**
 * OAuth2 related data accessor
 */

// NO IBM CONFIDENTIAL CODE OR INFORMATION!

public class OAuth2Accessor {
  public static enum Type {
    AUTHORIZATION_CODE
  }

  public static enum HttpMethod {
    GET, POST
  }

  public static enum OAuth2ParamLocation {
    URI_QUERY
  }

  private final OAuth2Provider provider;
  private final OAuth2Client client;

  private String authorizationCode;
  private String clientId;
  private String redirectUri;
  private String scope;
  private String state;
  private OAuth2Token accessToken;
  private OAuth2Token refreshToken;
  private String authorizationUrl;
  private String tokenUrl;

  public OAuth2Accessor(final OAuth2Provider provider, final OAuth2Client client) {
    this.provider = provider;
    this.client = client;
  }

  public OAuth2Provider getProvider() {
    return this.provider;
  }

  public OAuth2Client getClient() {
    return this.client;
  }

  public Type getAuthorizationType() {
    return Type.AUTHORIZATION_CODE;
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

  public String getState() {
    return this.state;
  }

  public void setState(final String state) {
    this.state = state;
  }

  public OAuth2Token getAccessToken() {
    return this.accessToken;
  }

  public void setAccessToken(final OAuth2Token accessToken) {
    this.accessToken = accessToken;
  }

  public OAuth2Token getRefreshToken() {
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

  public HttpMethod getMethod() {
    return HttpMethod.GET;
  }
}
