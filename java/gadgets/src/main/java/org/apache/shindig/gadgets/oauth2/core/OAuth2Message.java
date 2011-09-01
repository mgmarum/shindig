/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */
package org.apache.shindig.gadgets.oauth2.core;

//  NO IBM CONFIDENTIAL CODE OR INFORMATION!

import java.util.Map;

import org.apache.http.client.methods.HttpUriRequest;

public interface OAuth2Message {
  public Object addParameter(String name, Object value);

  public Object removeParameter(String name);

  public String getAuthorization();

  public Map<String, Object> getParameters();

  public String getBody();

  public Object getParameter(String name);

  public HttpUriRequest prepare();
}
