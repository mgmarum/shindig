package org.apache.shindig.gadgets.oauth2;

import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.shindig.auth.SecurityToken;
import org.apache.shindig.common.Pair;
import org.apache.shindig.common.crypto.BlobCrypter;
import org.apache.shindig.gadgets.http.HttpRequest;
import org.apache.shindig.gadgets.http.HttpResponse;
import org.apache.shindig.gadgets.http.HttpResponseBuilder;

import com.google.common.collect.Lists;

public class OAuth2ResponseParams {
  private static final Logger LOG = Logger.getLogger(OAuth2ResponseParams.class.getName());

  public static final String APPROVAL_URL = "oauthApprovalUrl";
  public static final String ERROR_CODE = "oauthError";
  public static final String ERROR_TEXT = "oauthErrorText";
  public static final String ERROR_URI = "oauthErrorUri";

  private final SecurityToken securityToken;
  private final HttpRequest originalRequest;
  private final List<Pair<HttpRequest, HttpResponse>> requestTrace = Lists.newArrayList();
  private String authorizationUrl;
  private boolean sendTraceToClient;

  public OAuth2ResponseParams(SecurityToken securityToken, HttpRequest originalRequest,
      BlobCrypter stateCrypter) {
    this.securityToken = securityToken;
    this.originalRequest = originalRequest;
  }

  /**
   * Log a warning message that includes the details of the request.
   */
  public void logDetailedWarning(String classname, String method, String msgKey) {
    if (LOG.isLoggable(Level.FINE)) {
      LOG.log(Level.FINE,getDetails(null));
    } else if (LOG.isLoggable(Level.WARNING)) {
    	LOG.logp(Level.WARNING, classname, method, msgKey, new Object[] {getDetails(null)});
    }
  }

  /**
   * Log a warning message that includes the details of the request and the thrown exception.
   */
  public void logDetailedWarning(String classname, String method, String msgKey, Throwable e) {
    if (LOG.isLoggable(Level.FINE)) {
      LOG.log(Level.FINE, getDetails(e), e);
    } else if (LOG.isLoggable(Level.WARNING)) {
       LOG.logp(Level.WARNING, classname, method, msgKey, new Object[] {e.getMessage()});
    }
  }

  public void logDetailedInfo(String classname, String method, String msgKey, Throwable e) {
    if (LOG.isLoggable(Level.FINE)) {
      LOG.log(Level.FINE, getDetails(e), e);
    } else if (LOG.isLoggable(Level.INFO)) {
    	LOG.logp(Level.INFO, classname, method, msgKey, new Object[] {e.getMessage()});
    }
  }

  /**
   * Log a warning message that includes the details of the request.
   */
  public void logDetailedWarning(String note) {
    if (LOG.isLoggable(Level.FINE)) {
      LOG.log(Level.FINE, note + '\n' + getDetails(null));
    } else if (LOG.isLoggable(Level.WARNING)) {
      LOG.log(Level.WARNING, note);
    }
  }

  /**
   * Log a warning message that includes the details of the request and the thrown exception.
   */
  public void logDetailedWarning(String note, Throwable e) {
    if (LOG.isLoggable(Level.FINE)) {
      LOG.log(Level.FINE, note + '\n' + getDetails(e), e);
    } else if (LOG.isLoggable(Level.WARNING)) {
      LOG.log(Level.WARNING, note + ": " + e.getMessage());
    }
  }

  public void logDetailedInfo(String note, Throwable e) {
    if (LOG.isLoggable(Level.FINE)) {
      LOG.log(Level.FINE, note + '\n' + getDetails(e), e);
    } else if (LOG.isLoggable(Level.INFO)) {
      LOG.log(Level.INFO, note + ": " + e.getMessage());
    }
  }

  /**
   * Add a request/response pair to our trace of actions associated with this request.
   */
  public void addRequestTrace(HttpRequest request, HttpResponse response) {
    this.requestTrace.add(Pair.of(request, response));
  }

  /**
   * @return true if the target server returned an error at some point during the request
   */
  public boolean sawErrorResponse() {
    for (Pair<HttpRequest, HttpResponse> event : requestTrace) {
      if (event.two == null || event.two.isError()) {
        return true;
      }
    }
    return false;
  }

  private String getDetails(Throwable e) {
    String error = null;

    if (null != e) {
      if(e instanceof OAuth2RequestException) {
        OAuth2RequestException reqException = ((OAuth2RequestException) e);
        error = reqException.getError() + ", " + reqException.getErrorText();
      }
      else {
        error = e.getMessage();
      }
    }

    return "OAuth error [" + error + "] for application "
        + securityToken.getAppUrl() + ".  Request trace:" + getRequestTrace();
  }

  private String getRequestTrace() {
    StringBuilder trace = new StringBuilder();
    trace.append("\n==== Original request:\n");
    trace.append(originalRequest);
    trace.append("\n====");
    int i = 1;
    for (Pair<HttpRequest, HttpResponse> event : requestTrace) {
      trace.append("\n==== Sent request ").append(i).append(":\n");
      if (event.one != null) {
        trace.append(event.one.toString());
      }
      trace.append("\n==== Received response ").append(i).append(":\n");
      if (event.two != null) {
        trace.append(event.two.toString());
      }
      trace.append("\n====");
      ++i;
    }
    return trace.toString();
  }

  public void addToResponse(HttpResponseBuilder response, OAuth2RequestException e) {
    if (this.authorizationUrl != null) {
      response.setMetadata(APPROVAL_URL, this.authorizationUrl);
    }

    if (e != null || sendTraceToClient) {
      StringBuilder verboseError = new StringBuilder();

      if (e != null) {
        response.setMetadata(ERROR_CODE, e.getError());
        verboseError.append(e.getErrorText());
      }
      if (sendTraceToClient) {
        verboseError.append('\n');
        verboseError.append(getRequestTrace());
      }

      response.setMetadata(ERROR_TEXT, verboseError.toString());
    }
  }

  public String getAuthorizationUrl() {
    return this.authorizationUrl;
  }

  public void setAuthorizationUrl(String authorizationUrl) {
    this.authorizationUrl = authorizationUrl;
  }

  public boolean sendTraceToClient() {
    return sendTraceToClient;
  }

  public void setSendTraceToClient(boolean sendTraceToClient) {
    this.sendTraceToClient = sendTraceToClient;
  }
}
