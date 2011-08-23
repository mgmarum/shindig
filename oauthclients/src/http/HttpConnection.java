package http;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.client.utils.URLEncodedUtils;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;

/**
 * Wraps all HTTP communication for insulation from library-specific APIs.
 * Currently uses Apache HttpClient for HTTP communications.
 */
public class HttpConnection {
  
  protected HttpClient httpClient;  // performs HTTP requests
  
  /**
   * Constructs this HTTP client.
   */
  public HttpConnection() {
    httpClient = new DefaultHttpClient();
  }

	/**
	 * Performs an HTTP GET.
	 * 
	 * @param url identifies the resource to send this request to
	 * @param headers are the request's HTTP headers
	 * @param params are the request's parameters
	 * 
	 * @return HTTPResponse represents the end point's response
	 */
  public Response get(String url, Map<String, String> headers, Map<String, String> params) {
    // Compose parameters
    Map<String, String> reqParams = addDefaultParams(new HashMap<String, String>());
    if (params != null) reqParams.putAll(params);
    
    // Compose headers
    Map<String, String> reqHeaders = addDefaultHeaders(new HashMap<String, String>());
    if (headers != null) reqHeaders.putAll(headers);
    
    // Create request
    HttpGet req = new HttpGet(buildUrl(url, params));
    for (String key : new TreeSet<String>(reqHeaders.keySet())) {
      req.addHeader(key, reqHeaders.get(key));
    }
    
    // Execute and return
    try {
      return new Response(httpClient.execute(req));
    } catch (ClientProtocolException e) {
      e.printStackTrace();
    } catch (IOException e) {
      e.printStackTrace();
    }
    throw new RuntimeException("GET request failed");
  }

  /**
   * Performs an HTTP PUT.
   * 
   * @param url identifies the resource to send this request to
   * @param headers are the request's HTTP headers
   * @param params are the request's parameters
   * @param body is the request's body content
   * 
   * @return HTTPResponse represents the end point's response
   */
  public Response put(String url, Map<String, String> headers, Map<String, String> params, String body) {
    // Compose parameters
    Map<String, String> reqParams = addDefaultParams(new HashMap<String, String>());
    if (params != null) reqParams.putAll(params);
    
    // Compose headers
    Map<String, String> reqHeaders = addDefaultHeaders(new HashMap<String, String>());
    if (headers != null) reqHeaders.putAll(headers);
    
    // Create request
    HttpPut req = new HttpPut(buildUrl(url, params));
    try {
      StringEntity entity = new StringEntity(body, "UTF-8");
      req.setEntity(entity);
    } catch (UnsupportedEncodingException e1) {
      e1.printStackTrace();
    }
    for (String key : new TreeSet<String>(reqHeaders.keySet())) {
      req.addHeader(key, reqHeaders.get(key));
    }
    
    // Execute and return
    try {
      return new Response(httpClient.execute(req));
    } catch (ClientProtocolException e) {
      e.printStackTrace();
    } catch (IOException e) {
      e.printStackTrace();
    }
    throw new RuntimeException("PUT request failed");
  }

  /**
   * Performs an HTTP POST.
   * 
   * @param url identifies the resource to send this request to
   * @param headers are the request's HTTP headers
   * @param params are the request's parameters
   * @param body is the request's body content
   * 
   * @return HTTPResponse represents the end point's response
   */
  public Response post(String url, Map<String, String> headers, Map<String, String> params, String body) {
    // Compose parameters
    Map<String, String> reqParams = addDefaultParams(new HashMap<String, String>());
    if (params != null) reqParams.putAll(params);
    
    // Compose headers
    Map<String, String> reqHeaders = addDefaultHeaders(new HashMap<String, String>());
    if (headers != null) reqHeaders.putAll(headers);
    
    // Create request
    HttpPost req = new HttpPost(buildUrl(url, params));
    try {
      StringEntity entity = new StringEntity(body, "UTF-8");
      req.setEntity(entity);
    } catch (UnsupportedEncodingException e1) {
      e1.printStackTrace();
    }
    for (String key : new TreeSet<String>(reqHeaders.keySet())) {
      req.addHeader(key, reqHeaders.get(key));
    }
    
    // Execute and return
    try {
      return new Response(httpClient.execute(req));
    } catch (ClientProtocolException e) {
      e.printStackTrace();
    } catch (IOException e) {
      e.printStackTrace();
    }
    throw new RuntimeException("POST request failed");
  }
  
  /**
   * Performs an HTTP DELETE.
   * 
   * @param url identifies the resource to send this request to
   * @param headers are the request's HTTP headers
   * @param params are the request's parameters
   * 
   * @return HTTPResponse represents the end point's response
   */
  public Response delete(String url, Map<String, String> headers, Map<String, String> params) {
    // Compose parameters
    Map<String, String> reqParams = addDefaultParams(new HashMap<String, String>());
    if (params != null) reqParams.putAll(params);
    
    // Compose headers
    Map<String, String> reqHeaders = addDefaultHeaders(new HashMap<String, String>());
    if (headers != null) reqHeaders.putAll(headers);
    
    // Create request
    HttpDelete req = new HttpDelete(buildUrl(url, params));
    for (String key : new TreeSet<String>(reqHeaders.keySet())) {
      req.addHeader(key, reqHeaders.get(key));
    }
    
    // Execute and return
    try {
      return new Response(httpClient.execute(req));
    } catch (ClientProtocolException e) {
      e.printStackTrace();
    } catch (IOException e) {
      e.printStackTrace();
    }
    throw new RuntimeException("DELETE request failed");
  }
  
  /**
   * Adds default headers to every HTTP request.  Subclasses should override
   * to add default headers.  Headers passed directly to CRUD operations take
   * precedence over default headers.
   * 
   * @param headers is the Map to add default headers to
   * 
   * @return Map<String, String> are the provided headers plus defaults 
   */
  public Map<String, String> addDefaultHeaders(Map<String, String> headers) {
    return headers;
  }
  
  /**
   * Adds default parameters to every HTTP request.  Subclasses should override
   * to add default parameters.  Parameters passed directly to CRUD operations
   * take precedence over default parameters.
   * 
   * @param params is the Map to add default parameters to
   * 
   * @return Map<String, String> are the provided parameters plus defaults
   */
  public Map<String, String> addDefaultParams(Map<String, String> params) {
    return params;
  }
  
  //------------------------------ PRIVATE HELPERS ----------------------------
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
   * @param parameters are parameters to add to the URL
   */
  public static String buildUrl(String url, Map<String, String> params) {
    if (params == null || params.isEmpty()) return url;
    try {
      URL uri = new URL(url);
      char appendChar = (uri.getQuery() == null || uri.getQuery().isEmpty()) ? '?' : '&';
      return url + appendChar + convertQueryString(params);
    } catch (MalformedURLException e) {
      e.printStackTrace();
      return null;
    }
  }
}
