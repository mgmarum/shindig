package org.apache.shindig.social.core.oauth2;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;
import org.apache.shindig.social.core.oauth2.OAuth2Types.ErrorType;
import org.apache.shindig.social.core.oauth2.OAuth2Types.GrantType;
import org.apache.shindig.social.core.oauth2.OAuth2Types.ResponseType;

/** 
 * Normalizes an OAuth 2.0 request by extracting OAuth 2.0 related fields.
 * 
 * TODO: error code lookup, mapping errors to descriptions
 * TODO: process lists (like scope) correctly
 * TODO: extensions allow crazy grant_types and response_types
 * TODO: extract client_secret from authorization token
 * TODO: redirect_uri for AT optional if not included in ACRequest; must use default then
 * TODO: normalize scope
 */
public class OAuth2NormalizedRequest extends HashMap<String, Object> {

  private static final long serialVersionUID = -7849581704967135322L;
  
  @SuppressWarnings("unchecked")
  public OAuth2NormalizedRequest(HttpServletRequest request) throws OAuth2Exception{
    super();
    normalizeBody(getBodyAsString(request));
    Enumeration<String> keys = request.getParameterNames();
    while (keys.hasMoreElements()) {
      String key = keys.nextElement();
      put(key, request.getParameter(key));
    }
    normalizeClientSecret(request);
    normalizeAccessToken(request);
  }
  
  // --------------------------- NORMALIZED GETTERS ---------------------------
  public String getClientId() {
    return getString("client_id");
  }
  
  public String getClientSecret() {
    return getString("client_secret");
  }
  
  public String getResponseType() {
    return getString("response_type");
  }
  
  public String getGrantType() {
    return getString("grant_type");
  }
  
  public String getRedirectUri() {
    return getString("redirect_uri");
  }
  
  public String getAccessToken() {
    return getString("access_token");
  }
  
  public String getAuthorizationCode() {
    return getString("code");
  }
  
  public String getState() {
    return getString("state");
  }
  
  private void normalizeAccessToken(HttpServletRequest req) {
    String bearerToken = getString("access_token");
    if(bearerToken == null || bearerToken.equals("")){
      String header = req.getHeader("Authorization");
      if(header != null && header.startsWith("Bearer")){
        String[] parts = header.split("\\s+");
        bearerToken = parts[parts.length-1];
      }
    }
    put("access_token", bearerToken);
  }
  
  public ResponseType getEnumeratedResponseType() throws OAuth2Exception {
    String respType = getResponseType();
    if (respType == null) return null;
    if (respType.equals("code")) {
      return ResponseType.CODE;
    } else if (respType.equals("token")) {
      return ResponseType.TOKEN;
    } else {
      throw new OAuth2Exception(ErrorType.UNSUPPORTED_RESPONSE_TYPE, "Unsupported response type");
    }
  }
  
  public GrantType getEnumeratedGrantType() {
    String grantType = getGrantType();
    if (grantType == null) return null;
    if (grantType.equals("refresh_token")) {
      return GrantType.REFRESH_TOKEN;
    } else if (grantType.equals("authorization_code")) {
      return GrantType.AUTHORIZATION_CODE;
    } else if (grantType.equals("password")) {
      return GrantType.PASSWORD;
    } else if (grantType.equals("client_credentials")) {
      return GrantType.CLIENT_CREDENTIALS;
    } else {
      return GrantType.CUSTOM;
    }
  }
  
  public String getString(String key) {
    if (!containsKey(key)) return null;
    return (String) get(key);
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
  
  // -------------------------- PRIVATE HELPERS -------------------------------
  private void normalizeClientSecret(HttpServletRequest request) {
    String secret = getString("client_secret");
    if(secret == null || secret.equals("")){
      String header = request.getHeader("Authorization");
      if(header != null && header.startsWith("Basic")){
        String[] parts = header.split("\\s+");
        String temp = parts[parts.length-1];
        byte[] decodedSecret = Base64.decodeBase64(temp);
        try {
          temp = new String(decodedSecret,"UTF-8");
          parts = temp.split(":");
          if(parts != null && parts.length == 2 && parts[0].equals(getString("client_id"))){
            secret = parts[1];
          }
        } catch (UnsupportedEncodingException e) {
          return;
        }
      }
    }
    put("client_secret", secret);
  }
  
  private void normalizeBody(String body) throws OAuth2Exception{
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
}
