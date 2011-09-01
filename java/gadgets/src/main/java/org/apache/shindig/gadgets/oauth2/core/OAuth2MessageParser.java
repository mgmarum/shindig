/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */
package org.apache.shindig.gadgets.oauth2.core;

//  NO IBM CONFIDENTIAL CODE OR INFORMATION!

import org.apache.http.HttpResponse;
import org.apache.shindig.gadgets.oauth2.OAuth2Exception;

public interface OAuth2MessageParser {
  public OAuth2Message parseResponse(HttpResponse response) throws OAuth2Exception;
}
