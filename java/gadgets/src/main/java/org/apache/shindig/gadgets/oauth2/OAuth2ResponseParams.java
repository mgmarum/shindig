package org.apache.shindig.gadgets.oauth2;

import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.shindig.auth.SecurityToken;
import org.apache.shindig.common.Pair;
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

  public OAuth2ResponseParams(final SecurityToken securityToken, final HttpRequest originalRequest) {
    this.securityToken = securityToken;
    this.originalRequest = originalRequest;
  }

  /**
   * Log a warning message that includes the details of the request.
   */
  public void logDetailedWarning(final String classname, final String method, final String msgKey) {
    if (OAuth2ResponseParams.LOG.isLoggable(Level.FINE)) {
      OAuth2ResponseParams.LOG.log(Level.FINE, this.getDetails(null));
    } else if (OAuth2ResponseParams.LOG.isLoggable(Level.WARNING)) {
      OAuth2ResponseParams.LOG.logp(Level.WARNING, classname, method, msgKey,
          new Object[] { this.getDetails(null) });
    }
  }

  /**
   * Log a warning message that includes the details of the request and the
   * thrown exception.
   */
  public void logDetailedWarning(final String classname, final String method, final String msgKey,
      final Throwable e) {
    if (OAuth2ResponseParams.LOG.isLoggable(Level.FINE)) {
      OAuth2ResponseParams.LOG.log(Level.FINE, this.getDetails(e), e);
    } else if (OAuth2ResponseParams.LOG.isLoggable(Level.WARNING)) {
      OAuth2ResponseParams.LOG.logp(Level.WARNING, classname, method, msgKey,
          new Object[] { e.getMessage() });
    }
  }

  public void logDetailedInfo(final String classname, final String method, final String msgKey,
      final Throwable e) {
    if (OAuth2ResponseParams.LOG.isLoggable(Level.FINE)) {
      OAuth2ResponseParams.LOG.log(Level.FINE, this.getDetails(e), e);
    } else if (OAuth2ResponseParams.LOG.isLoggable(Level.INFO)) {
      OAuth2ResponseParams.LOG.logp(Level.INFO, classname, method, msgKey,
          new Object[] { e.getMessage() });
    }
  }

  /**
   * Log a warning message that includes the details of the request.
   */
  public void logDetailedWarning(final String note) {
    if (OAuth2ResponseParams.LOG.isLoggable(Level.FINE)) {
      OAuth2ResponseParams.LOG.log(Level.FINE, note + '\n' + this.getDetails(null));
    } else if (OAuth2ResponseParams.LOG.isLoggable(Level.WARNING)) {
      OAuth2ResponseParams.LOG.log(Level.WARNING, note);
    }
  }

  /**
   * Log a warning message that includes the details of the request and the
   * thrown exception.
   */
  public void logDetailedWarning(final String note, final Throwable e) {
    if (OAuth2ResponseParams.LOG.isLoggable(Level.FINE)) {
      OAuth2ResponseParams.LOG.log(Level.FINE, note + '\n' + this.getDetails(e), e);
    } else if (OAuth2ResponseParams.LOG.isLoggable(Level.WARNING)) {
      OAuth2ResponseParams.LOG.log(Level.WARNING, note + ": " + e.getMessage());
    }
  }

  public void logDetailedInfo(final String note, final Throwable e) {
    if (OAuth2ResponseParams.LOG.isLoggable(Level.FINE)) {
      OAuth2ResponseParams.LOG.log(Level.FINE, note + '\n' + this.getDetails(e), e);
    } else if (OAuth2ResponseParams.LOG.isLoggable(Level.INFO)) {
      OAuth2ResponseParams.LOG.log(Level.INFO, note + ": " + e.getMessage());
    }
  }

  /**
   * Add a request/response pair to our trace of actions associated with this
   * request.
   */
  public void addRequestTrace(final HttpRequest request, final HttpResponse response) {
    this.requestTrace.add(Pair.of(request, response));
  }

  /**
   * @return true if the target server returned an error at some point during
   *         the request
   */
  public boolean sawErrorResponse() {
    for (final Pair<HttpRequest, HttpResponse> event : this.requestTrace) {
      if ((event.two == null) || event.two.isError()) {
        return true;
      }
    }
    return false;
  }

  private String getDetails(final Throwable e) {
    String error = null;

    if (null != e) {
      if (e instanceof OAuth2RequestException) {
        final OAuth2RequestException reqException = ((OAuth2RequestException) e);
        error = reqException.getError() + ", " + reqException.getErrorText();
      } else {
        error = e.getMessage();
      }
    }

    return "OAuth error [" + error + "] for application " + this.securityToken.getAppUrl()
        + ".  Request trace:" + this.getRequestTrace();
  }

  private String getRequestTrace() {
    final StringBuilder trace = new StringBuilder();
    trace.append("\n==== Original request:\n");
    trace.append(this.originalRequest);
    trace.append("\n====");
    int i = 1;
    for (final Pair<HttpRequest, HttpResponse> event : this.requestTrace) {
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

  public void addToResponse(final HttpResponseBuilder response, final OAuth2RequestException e) {
    if (this.authorizationUrl != null) {
      response.setMetadata(OAuth2ResponseParams.APPROVAL_URL, this.authorizationUrl);
    }

    if ((e != null) || this.sendTraceToClient) {
      final StringBuilder verboseError = new StringBuilder();

      if (e != null) {
        response.setMetadata(OAuth2ResponseParams.ERROR_CODE, e.getError());
        verboseError.append(e.getErrorText());
      }
      if (this.sendTraceToClient) {
        verboseError.append('\n');
        verboseError.append(this.getRequestTrace());
      }

      response.setMetadata(OAuth2ResponseParams.ERROR_TEXT, verboseError.toString());
    }
  }

  public String getAuthorizationUrl() {
    return this.authorizationUrl;
  }

  public void setAuthorizationUrl(final String authorizationUrl) {
    this.authorizationUrl = authorizationUrl;
  }

  public boolean sendTraceToClient() {
    return this.sendTraceToClient;
  }

  public void setSendTraceToClient(final boolean sendTraceToClient) {
    this.sendTraceToClient = sendTraceToClient;
  }
}
