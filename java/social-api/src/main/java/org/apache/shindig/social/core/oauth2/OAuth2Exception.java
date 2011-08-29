package org.apache.shindig.social.core.oauth2;

import org.apache.shindig.social.core.oauth2.OAuth2Types.ErrorType;


/**
 * Represents an exception while dancing with OAuth 2.0.
 * 
 * TODO: Completely remove other constructors.
 */
public class OAuth2Exception extends Exception {

  private static final long serialVersionUID = -5892464438773813010L;
  private OAuth2NormalizedResponse response;

  public OAuth2Exception(String msg) {
    super(msg);
  }
  
  public OAuth2Exception(OAuth2NormalizedResponse response) {
	  super(response.getErrorDescription());
	  this.response = response;
  }
  
  public OAuth2Exception(ErrorType errorType, String errorDescription) {
	  super(errorDescription);
	  this.response = new OAuth2NormalizedResponse();
	  response.setError(errorType.toString());
	  response.setErrorDescription(errorDescription);
  }
  
  public OAuth2Exception(String msg, Throwable cause){
    super(msg,cause);
  }
  
  public OAuth2Exception(Throwable cause){
    super(cause);
  }
  
  public OAuth2NormalizedResponse getNormalizedResponse() {
	  return response;
  }
}
