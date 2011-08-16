package org.apache.shindig.social.core.oauth2X;

import org.apache.shindig.social.core.oauth2X.OAuth2Types.ErrorType;

/**
 * Represents an exception in OAuth 2.0 handshakes.
 * 
 * TODO: probably shouldn't extend from RuntimeException
 * TODO: probably add Map<String, String> for error response body
 */
public class OAuth2Exception extends RuntimeException {

  private static final long serialVersionUID = -5892464438773813010L;
  private ErrorType errorType;
  private String errorDescription;

  public OAuth2Exception(String msg) {
    super(msg);
  }
  
  public OAuth2Exception(String msg, Throwable cause){
    super(msg,cause);
  }
  
  public OAuth2Exception(Throwable cause){
    super(cause);
  }
  
  public OAuth2Exception(ErrorType errorType, String errorDescription) {
    this.errorType = errorType;
    this.errorDescription = errorDescription;
  }
  
  public ErrorType getErrorType() {
    return errorType;
  }
  
  public String getErrorDescription() {
    return errorDescription;
  }
}
