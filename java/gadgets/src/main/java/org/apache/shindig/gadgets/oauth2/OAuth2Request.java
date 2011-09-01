/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */
package org.apache.shindig.gadgets.oauth2;

import java.util.List;

import org.apache.shindig.gadgets.http.HttpRequest;
import org.apache.shindig.gadgets.http.HttpResponse;
import org.apache.shindig.gadgets.oauth2.core.Parameter;

// NO IBM CONFIDENTIAL CODE OR INFORMATION!

public interface OAuth2Request {
  public HttpResponse fetch(HttpRequest request);

  public HttpRequest sanitizeAndSign(HttpRequest arg0, List<Parameter> arg1, boolean arg2)
      throws OAuth2RequestException;
}
