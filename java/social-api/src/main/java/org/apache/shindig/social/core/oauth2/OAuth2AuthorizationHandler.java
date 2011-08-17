package org.apache.shindig.social.core.oauth2;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;
import org.apache.http.message.BasicNameValuePair;
import org.apache.shindig.social.core.oauth2.OAuth2Types.ResponseType;

/**
 * NOTE: I plan to bloat handle(), then re-factor into a "logic-tree" later... This is where it all comes together!!!
 * 
 * TODO: If 'Authorization' header used, must reply with WWW something
 */
public class OAuth2AuthorizationHandler {
  
  private OAuth2Service service;
  
  public OAuth2AuthorizationHandler(OAuth2Service service) {
    this.service = service;
  }
  
  public void handle(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {   
    try {
      OAuth2NormalizedRequest normalizedReq = new OAuth2NormalizedRequest(request);
      System.out.println("Normalized token request: ");
      System.out.println(normalizedReq.toString());
      if (normalizedReq.containsKey("response_type")) {
        switch ((ResponseType) normalizedReq.get("response_type")) {
        case CODE:
          // authorization code dance
          service.authenticateClient(normalizedReq);
          service.validateRequestForAuthCode(normalizedReq);
          authorizeClient(request, response);
          OAuth2Code authCode = service.generateAuthorizationCode(normalizedReq);
          service.registerAuthorizationCode(normalizedReq.getString("client_id"), authCode);
          
          // formulate response
          Map<String, String> returnParams = new HashMap<String, String>();
          returnParams.put("code", authCode.getValue());
          if (normalizedReq.containsKey("state")) {
            returnParams.put("state", normalizedReq.getString("state"));
          }
          response.setHeader("Location", buildUrl(authCode.getRedirectUri(), returnParams));
          response.setStatus(HttpServletResponse.SC_FOUND);
          break;
        case TOKEN: // requesting access token, IMPLICIT FLOW
          // TODO: implement
          break;
        default:
          // TODO: unrecognized - throw error
          break;
        }
      }
    } catch(OAuth2Exception oae) {
      // TODO: better error processing
      response.sendError(HttpServletResponse.SC_FORBIDDEN, oae.getLocalizedMessage());
    }
  }
  
  private void authorizeClient(HttpServletRequest request, HttpServletResponse response) {
    // TODO: return screen for user to "allow" or "deny"; current implementation doesn't work, need to validate client first
  }
  
  // ---------------------------- PRIVATE UTILITIES ---------------------------
  
  /**
   * Converts a Map<String, String> to a URL query string.
   * 
   * @param params represents the Map of query parameters
   * 
   * @return String is the URL encoded parameter String
   */
  private String convertQueryString(Map<String, String> params) {
    if (params == null) return "";
    List<NameValuePair> nvp = new ArrayList<NameValuePair>();
    for (String key : new TreeSet<String>(params.keySet())) {
      if (params.get(key) != null) {
        nvp.add(new BasicNameValuePair(key, params.get(key)));
      }
    }
    return URLEncodedUtils.format(nvp, "UTF-8");
  }
  
  /**
   * Normalizes a URL and parameters.  If the URL already contains parameters,
   * new parameters will be added properly.
   * 
   * @param URL is the base URL to normalize
   * @param parameters are parameters to add to the URL
   */
  private String buildUrl(String url, Map<String, String> params) {
    if (params == null || params.isEmpty()) return url;
    StringBuffer buff = new StringBuffer(url);
//    try {
      //URL validation is tricky.. this doesn't allow relative URLs, for example, which is valid from an HTTP perspective.
//      URL uri = new URL(url);
    if(url.contains("?")){
      buff.append('&');
    } else {
      buff.append('?');
    }
    buff.append(convertQueryString(params));
    return buff.toString();
//    } catch (MalformedURLException e) {
//      e.printStackTrace();
//      return null;
//    }
  }
}
