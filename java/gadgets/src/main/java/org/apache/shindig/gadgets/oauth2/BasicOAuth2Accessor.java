package org.apache.shindig.gadgets.oauth2;

public class BasicOAuth2Accessor implements OAuth2Accessor {
  /**
   * 
   */
  private static final long serialVersionUID = 1L;
  private OAuth2Token accessToken;
  private final boolean allowModuleOverrides;
  private String authorizationUrl;
  private String clientAuthenticationType;
  private String clientId;
  private String clientSecret;
  private final String gadgetUri;
  private String grantType;
  private String realCallbackUrl;
  private String realErrorCallbackUrl;
  private String redirectUri;
  private OAuth2Token refreshToken;
  private final String scope;
  private final String serviceName;
  private final String state;
  private String tokenUrl;
  private Type type;
  private final String user;

  public BasicOAuth2Accessor(final String gadgetUri, final String serviceName, final String user,
      final String scope, final boolean allowModuleOverrides, final OAuth2Store store) {
    this.gadgetUri = gadgetUri;
    this.serviceName = serviceName;
    this.user = user;
    this.scope = scope;
    this.allowModuleOverrides = allowModuleOverrides;
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
    this.realCallbackUrl = accessor.getRealCallbackUrl();
    this.realErrorCallbackUrl = accessor.getRealErrorCallbackUrl();
    this.redirectUri = accessor.getRedirectUri();
    this.refreshToken = accessor.getRefreshToken();
    this.serviceName = accessor.getServiceName();
    this.scope = accessor.getScope();
    this.state = accessor.getState();
    this.tokenUrl = accessor.getTokenUrl();
    this.type = accessor.getType();
    this.user = accessor.getUser();
    this.allowModuleOverrides = false;
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

  public String getRealCallbackUrl() {
    return this.realCallbackUrl;
  }

  public void setRealCallbackUrl(final String realCallbackUrl) {
    this.realCallbackUrl = realCallbackUrl;
  }

  public String getRealErrorCallbackUrl() {
    return this.realErrorCallbackUrl;
  }

  public void setRealErrorCallbackUrl(final String realErrorCallbackUrl) {
    this.realErrorCallbackUrl = realErrorCallbackUrl;
  }

  public String getRedirectUri() {
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
