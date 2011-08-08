package org.apache.shindig.social.core.oauth2;

public class OAuth2Exception extends Exception {
  
  /**
   * 
   */
  private static final long serialVersionUID = 1L;

  protected OAuth2Exception() {

  }
  
  public OAuth2Exception(String msg){
    super(msg);
  }
  
  public OAuth2Exception(String msg, Throwable cause){
    super(msg,cause);
  }
  
  public OAuth2Exception(Throwable cause){
    super(cause);
  }

}
