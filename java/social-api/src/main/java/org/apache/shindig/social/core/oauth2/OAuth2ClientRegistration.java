package org.apache.shindig.social.core.oauth2;

public class OAuth2ClientRegistration {
  
  private String clientId = "";
  private String clientSecret = "";
  private ClientType type = ClientType.PUBLIC;
  private String redirectionURI = "";
  
  
  public enum ClientType{
    CONFIDENTIAL, PUBLIC
  }


  public String getClientId() {
    return clientId;
  }


  public void setClientId(String clientId) {
    this.clientId = clientId;
  }


  public String getClientSecret() {
    return clientSecret;
  }


  public void setClientSecret(String clientSecret) {
    this.clientSecret = clientSecret;
  }


  public ClientType getType() {
    return type;
  }


  public void setType(ClientType type) {
    this.type = type;
  }


  public void setRedirectionURI(String redirectionURI) {
    this.redirectionURI = redirectionURI;
  }


  public String getRedirectionURI() {
    return redirectionURI;
  }
  
  
  

}
