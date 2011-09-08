package org.apache.shindig.gadgets.oauth2;

public class OAuth2Message {
  private String authorizationCode;

  public String getAuthorizationCode() {
    return this.authorizationCode;
  }

  public void setAuthorizationCode(final String authorizationCode) {
    this.authorizationCode = authorizationCode;
  }
}
