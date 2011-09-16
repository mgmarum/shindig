/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */
package org.apache.shindig.gadgets.oauth2.handler;

import javax.servlet.http.HttpServletRequest;

import org.apache.shindig.gadgets.http.HttpResponse;
import org.apache.shindig.gadgets.oauth2.OAuth2Accessor;
import org.apache.shindig.gadgets.oauth2.OAuth2Message;

//NO IBM CONFIDENTIAL CODE OR INFORMATION!

public interface AuthorizationEndpointResponseHandler {
  public boolean handlesRequest(OAuth2Accessor accessor, HttpServletRequest request);

  public boolean handlesResponse(OAuth2Accessor accessor, HttpResponse response);

  public OAuth2Message handleResponse(OAuth2Accessor accessor, HttpResponse response);

  public OAuth2Message handleRequest(OAuth2Accessor accessor, HttpServletRequest request);
}