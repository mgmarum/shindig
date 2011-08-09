package org.apache.shindig.social.core.oauth2;

public class OAuth2Token {
  
  public enum TokenType{
    ACCESS, REFRESH
  }
  
  private TokenType type = TokenType.ACCESS;
  
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

}
