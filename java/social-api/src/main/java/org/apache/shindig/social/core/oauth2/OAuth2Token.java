package org.apache.shindig.social.core.oauth2;


import java.util.List;

public class OAuth2Token extends OAuth2Code{
  
  public enum TokenType{
    ACCESS, REFRESH
  }
  
  private TokenType type = TokenType.ACCESS;
  private OAuth2Code associatedCode;
  
  public OAuth2Token(){
    
  }
  
  public OAuth2Token(String value){
    super(value);
  }
  
  public OAuth2Token(String value, String redirectUri, long expiration, List<String> scope, OAuth2Code authCode) {
    super(value,redirectUri,expiration,scope);
    associatedCode = authCode;
  }
  
  /**
   * Not sure why this is needed?
   * @return
   */
  public OAuth2Code getAssociatedCode() {
    return associatedCode;
  }
  
  public void setAssociatedCode(OAuth2Code authCode) {
    this.associatedCode = authCode;
  }

  public void setType(TokenType type) {
    this.type = type;
  }

  public TokenType getType() {
    return type;
  }
  

}
