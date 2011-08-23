package http;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeSet;

import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;

/**
 * Represents an HTTP response for HTTP requests.
 * 
 * TODO: Dangerous - getBodyStream() can consume stream, then getBody() will fail, vice versa
 * TODO: consuming stream immediately, remove getBodyStream()?
 * TODO: Comment these methods.
 */
public class Response {

  protected String phrase;                // HTTP reason phrase
  protected int statusCode;               // HTTP status code
  protected Map<String, String> headers;  // HTTP response headers
  protected String body;                  // HTTP response body as string
  protected InputStream bodyStream;       // HTTP response body as stream
  protected long length;                  // length of body stream
  protected String type;                  // type of body stream
  protected String encoding;              // encoding of body stream
  
  /**
   * Default constructor.
   */
  public Response() {
    this.phrase = null;
    this.statusCode = -1;
    this.headers = null;
    this.body = null;
    this.bodyStream = null;
    this.length = -1;
    this.type = null;
    this.encoding = null;
  }
  
  /**
   * Constructs Response from an HttpResponse from HttpClient.
   * 
   * @param resp is the HttpResponse from HttpClient
   */
  public Response(HttpResponse resp) {
    phrase = resp.getStatusLine().getReasonPhrase();
    statusCode = resp.getStatusLine().getStatusCode();
    headers = new HashMap<String, String>();
    for (Header header : resp.getAllHeaders()) {
      this.headers.put(header.getName(), header.getValue());
    }
    
    // Handle response entity
    HttpEntity entity = resp.getEntity();
    if (entity != null) {
      try {
        this.bodyStream = entity.getContent();
        this.body = getBody();
        this.length = entity.getContentLength();
        if (entity.getContentType() != null) this.type = entity.getContentType().getValue();
        if (entity.getContentEncoding() != null) this.encoding = entity.getContentEncoding().getValue();
      } catch (IllegalStateException ise) {
        ise.printStackTrace();
      } catch (IOException ioe) {
        ioe.printStackTrace();
      }
    } else {
      body = null;
      bodyStream = null;
      length = -1;
      type = null;
      encoding = null;
    }
  }
  
  public String getPhrase() {
    return phrase;
  }
  
  public int getStatusCode() {
    return statusCode;
  }
  
  public Map<String, String> getHeaders() {
    return headers;
  }
  
  public String getBody() {
    // Can only consume once
    if (body != null) return body;
    
    // No response if stream is null
    if (bodyStream == null) return "";
        
    // Lets consume some InputStream
    try {
      String line = null;
      StringBuffer sb = new StringBuffer();
      BufferedReader reader = new BufferedReader(new InputStreamReader(bodyStream));
      while ((line = reader.readLine()) != null) {
        sb.append(line);
      }
      bodyStream.close();
      body = sb.toString();
      return body;
    } catch (IOException ioe) {
      ioe.printStackTrace();
    }
    return null;
  }
  
  public InputStream getBodyStream() {
    return bodyStream;
  }
  
  public long getLength() {
    return length;
  }
  
  public String getType() {
    return type;
  }
  
  public String getEncoding() {
    return encoding;
  }
  
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("Phrase: " + getPhrase() + '\n');
    sb.append("Status: " + getStatusCode() + '\n');
    sb.append("Length: " + getLength() + '\n');
    sb.append("Type: " + getType() + '\n');
    sb.append("Encoding: " + getEncoding() + '\n');
    sb.append("Headers:\n");
    for(String key : new TreeSet<String>(getHeaders().keySet())) {
      sb.append('\t' + key + ": " + getHeaders().get(key) + '\n');
    }
    sb.append("Body: \n\t" + getBody());
    return sb.toString();
  }
}