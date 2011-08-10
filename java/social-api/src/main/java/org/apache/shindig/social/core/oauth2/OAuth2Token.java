package org.apache.shindig.social.core.oauth2;

public class OAuth2Token {
  
  public enum TokenType{
    ACCESS, REFRESH
  }
  
  private TokenType type = TokenType.ACCESS;
  
  private OAuth2ClientRegistration clientReg;
  
  private String id;
  
  
  public OAuth2Token(String id){
    this.setId(id);
  }


  public void setType(TokenType type) {
    this.type = type;
  }


  public TokenType getType() {
    return type;
  }


  public void setId(String id) {
    this.id = id;
  }


  public String getId() {
    return id;
  }


  public void setClientReg(OAuth2ClientRegistration clientReg) {
    this.clientReg = clientReg;
  }


  public OAuth2ClientRegistration getClientReg() {
    return clientReg;
  }

}
