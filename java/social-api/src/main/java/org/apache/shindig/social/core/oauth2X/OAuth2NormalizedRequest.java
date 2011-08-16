package org.apache.shindig.social.core.oauth2X;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;
import org.apache.shindig.social.core.oauth2X.OAuth2Types.ErrorType;
import org.apache.shindig.social.core.oauth2X.OAuth2Types.GrantType;
import org.apache.shindig.social.core.oauth2X.OAuth2Types.ResponseType;

/** 
 * Normalizes an OAuth 2.0 request by extracting OAuth 2.0 related fields.
 * 
 * TODO: error code lookup, mapping errors to descriptions
 * TODO: process lists (like scope) correctly
 * TODO: extensions allow crazy grant_types and response_types
 * TODO: extract client_secret from authorization token
 * TODO: redirect_uri for AT optional if not included in ACRequest; must use default then
 */
public class OAuth2NormalizedRequest extends HashMap<String, Object> {

  private static final long serialVersionUID = -7849581704967135322L;
  
  @SuppressWarnings("unchecked")
  public OAuth2NormalizedRequest(HttpServletRequest request) {
    Enumeration<String> keys = request.getParameterNames();
    while (keys.hasMoreElements()) {
      String key = keys.nextElement();
      put(key, request.getParameter(key));
    }
    normalizeBody(getBodyAsString(request));
    normalizeAuthorizationHeader(request);
    normalizeScope();
    normalizeGrantType();
    normalizeResponseType();
  }
  
  public String getString(String key) {
    return (String) get(key);
  }
  
  private void normalizeResponseType() {
    if(containsKey("response_type")) {
      String respType = (String) get("response_type");
      if (respType.equals(ResponseType.CODE.toString())) {
        put("response_type", ResponseType.CODE);
      } else if (respType.equals(ResponseType.TOKEN.toString())) {
        put("response_type", ResponseType.TOKEN);
      } else {
        throw new OAuth2Exception(ErrorType.UNSUPPORTED_RESPONSE_TYPE, "response_type not supported");
      }
    }
  }
  
  private void normalizeGrantType() {
    if(containsKey("grant_type")) {
      String respType = (String) get("grant_type");
      if (respType.equals(GrantType.REFRESH_TOKEN.toString())) {
        put("grant_type", GrantType.REFRESH_TOKEN);
      } else if (respType.equals(GrantType.AUTHORIZATION_CODE.toString())) {
        put("grant_type", GrantType.AUTHORIZATION_CODE);
      } else if (respType.equals(GrantType.PASSWORD.toString())) {
        put("grant_type", GrantType.PASSWORD);
      } else if (respType.equals(GrantType.CLIENT_CREDENTIALS.toString())) {
        put("grant_type", GrantType.CLIENT_CREDENTIALS);
      } else {
        throw new OAuth2Exception(ErrorType.UNSUPPORTED_GRANT_TYPE, "grant_type not supported");
      }
    }
  }
  
  private void normalizeScope() {
    // TODO: implement this
  }
  
  private void normalizeAuthorizationHeader(HttpServletRequest request) {
    // TODO: implement this
  }
  
  private void normalizeBody(String body) {
    if (body == null || body.isEmpty()) return;
    List<NameValuePair> params;
    try {
      params = URLEncodedUtils.parse(new URI("http://localhost:8080?" + body), "UTF-8");
      for (NameValuePair param : params) {
        put(param.getName(), param.getValue());
      }
    } catch (URISyntaxException e) {
      throw new OAuth2Exception(ErrorType.INVALID_REQUEST, "The message body's syntax is incorrect");
    }
  }
  
  private String getBodyAsString(HttpServletRequest request) {
    if (request.getContentLength() == 0) return "";
    try {
      String line = null;
      StringBuffer sb = new StringBuffer();
      InputStream is = request.getInputStream();
      BufferedReader reader = new BufferedReader(new InputStreamReader(is));
      while ((line = reader.readLine()) != null) {
        sb.append(line);
      }
      is.close();
      return sb.toString();
    } catch (IOException ioe) {
      ioe.printStackTrace();
      return null;
    }
  }
  
  public String toString() {
    StringBuilder sb = new StringBuilder();
    for (String key : keySet()) {
      sb.append(key);
      sb.append(": ");
      sb.append(get(key));
      sb.append('\n');
    }
    return sb.toString();
  }
}
