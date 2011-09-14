/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */
package org.apache.shindig.gadgets.oauth2;

import javax.servlet.http.HttpServletRequest;

//NO IBM CONFIDENTIAL CODE OR INFORMATION!

public interface OAuth2AuthorizationResponseHandler {
  public String[] getResponseTypes();
  
  public OAuth2Message handleRequest(HttpServletRequest request);
}
