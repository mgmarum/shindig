/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */
package org.apache.shindig.gadgets.oauth2;

//NO IBM CONFIDENTIAL CODE OR INFORMATION!

public interface OAuth2GrantTypeHandler {
  public String getGrantType();
  
  public String getResponseType();
    
  public String getAuthorizationBody(OAuth2Accessor accessor,  String authorizationCode) throws OAuth2RequestException;
  
  public String getCompleteAuthorizationUrl(String authorizationUrl, OAuth2Accessor accessor) throws OAuth2RequestException;
}
