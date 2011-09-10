package org.apache.shindig.gadgets.oauth2;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;
import org.apache.http.message.BasicNameValuePair;
import org.apache.shindig.gadgets.http.HttpRequest;
import org.apache.shindig.gadgets.http.HttpResponse;

public class OAuth2Utils {
  
  public static String fetchBearerTokenFromHttpRequest(HttpServletRequest req){
    String bearerToken = req.getParameter("access_token");
    if(bearerToken == null || bearerToken.equals("")){
      String header = req.getHeader("Authorization");
      if(header != null && header.contains("Bearer")){
        String[] parts = header.split("\\s+");
        bearerToken = parts[parts.length-1];
      }
    }
    return bearerToken;
  }
  
  public static String fetchClientSecretFromHttpRequest(String clientId, HttpServletRequest req){
    String secret = req.getParameter("client_secret");
    if(secret == null || secret.equals("")){
      String header = req.getHeader("Authorization");
      if(header != null && header.contains("Basic")){
        String[] parts = header.split("\\s+");
        String temp = parts[parts.length-1];
        byte[] decodedSecret = Base64.decodeBase64(secret);
        try {
          temp = new String(decodedSecret,"UTF-8");
          parts = temp.split(":");
          if(parts != null && parts.length == 2 && parts[0] == clientId){
            secret = parts[1];
          }
        } catch (UnsupportedEncodingException e) {
          return null;
        }
      }
    }
    return secret;
  }
  
  /**
   * Converts a Map<String, String> to a URL query string.
   * 
   * @param params represents the Map of query parameters
   * 
   * @return String is the URL encoded parameter String
   */
  public static String convertQueryString(Map<String, String> params) {
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
   * @param queryParams query parameters to add to the URL
   * @param fragmentParams fragment params to add to the URL
   */
  public static String buildUrl(String url, Map<String, String> queryParams, Map<String,String> fragmentParams) {
    StringBuffer buff = new StringBuffer(url);
    if (queryParams != null && !queryParams.isEmpty()){
      if(url.contains("?")){
        buff.append('&');
      } else {
        buff.append('?');
      }
      buff.append(convertQueryString(queryParams));
    }
    if (fragmentParams != null && !fragmentParams.isEmpty()){
      if(url.contains("#")){
        buff.append('&');
      } else {
        buff.append('#');
      }
      buff.append(convertQueryString(fragmentParams));
    }
    return buff.toString();
  }  
}
