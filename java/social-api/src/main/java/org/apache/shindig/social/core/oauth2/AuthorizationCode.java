package org.apache.shindig.social.core.oauth2;

public class AuthorizationCode {
  
  private String authCode;
  private String redirectURI;
  private OAuth2ClientRegistration client;
  
  public AuthorizationCode(String authCode, OAuth2ClientRegistration client){
    this.authCode = authCode;
    this.client = client;
  }

  public String getAuthCode() {
    return authCode;
  }

  public void setRedirectURI(String redirectURI) {
    this.redirectURI = redirectURI;
  }

  public String getRedirectURI() {
    return redirectURI;
  }

  public OAuth2ClientRegistration getClient() {
    return client;
  }

}
