/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */
package org.apache.shindig.gadgets.oauth2;

import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.shindig.auth.SecurityToken;
import org.apache.shindig.common.Pair;
import org.apache.shindig.common.crypto.BlobCrypter;
import org.apache.shindig.common.crypto.BlobCrypterException;
import org.apache.shindig.gadgets.http.HttpRequest;
import org.apache.shindig.gadgets.http.HttpResponse;
import org.apache.shindig.gadgets.http.HttpResponseBuilder;

import com.google.common.collect.Lists;

/**
 * Container for OAuth specific data to include in the response to the client.
 */

// NO IBM CONFIDENTIAL CODE OR INFORMATION!

public class OAuth2ResponseParams {
  private static final Logger LOG = Logger.getLogger(OAuth2ResponseParams.class.getName());

  // Finds the values of sensitive response params: oauth_token_secret and
  // oauth_session_handle
  private static final Pattern REMOVE_SECRETS = Pattern
      .compile("(?<=(oauth_token_secret|oauth_session_handle)=)[^=& \t\r\n]*");

  // names for the JSON values we return to the client
  public static final String CLIENT_STATE = "oauthState";
  public static final String APPROVAL_URL = "oauthApprovalUrl";
  public static final String ERROR_CODE = "oauthError";
  public static final String ERROR_TEXT = "oauthErrorText";

  /**
   * Transient state we want to cache client side.
   */
  private final OAuth2ClientState newClientState;

  /**
   * Security token used to authenticate request.
   */
  private final SecurityToken securityToken;

  /**
   * Original request from client.
   */
  private final HttpRequest originalRequest;

  /**
   * Request/response pairs we sent onward.
   */
  private final List<Pair<HttpRequest, HttpResponse>> requestTrace = Lists.newArrayList();

  /**
   * Authorization URL for the client.
   */
  private String aznUrl;

  /**
   * Whether we should include the request trace in the response to the
   * application.
   * 
   * It might be nice to make this configurable based on options passed to
   * makeRequest. For now we use some heuristics to figure it out.
   */
  private boolean sendTraceToClient;

  /**
   * Create response parameters.
   */
  public OAuth2ResponseParams(final SecurityToken securityToken, final HttpRequest originalRequest,
      final BlobCrypter stateCrypter) {
    this.securityToken = securityToken;
    this.originalRequest = originalRequest;
    this.newClientState = new OAuth2ClientState(stateCrypter);
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
        trace.append(OAuth2ResponseParams.filterSecrets(event.one.toString()));
      }
      trace.append("\n==== Received response ").append(i).append(":\n");
      if (event.two != null) {
        trace.append(OAuth2ResponseParams.filterSecrets(event.two.toString()));
      }
      trace.append("\n====");
      ++i;
    }
    return trace.toString();
  }

  /**
   * Removes security sensitive parameters from requests and responses.
   */
  static String filterSecrets(final String in) {
    final Matcher m = OAuth2ResponseParams.REMOVE_SECRETS.matcher(in);
    return m.replaceAll("REMOVED");
  }

  /**
   * Update a response with additional data to be returned to the application.
   */
  public void addToResponse(final HttpResponseBuilder response, final OAuth2RequestException e) {
    if (!this.newClientState.isEmpty()) {
      try {
        response.setMetadata(OAuth2ResponseParams.CLIENT_STATE,
            this.newClientState.getEncryptedState());
      } catch (final BlobCrypterException cryptException) {
        // Configuration error somewhere, this should never happen.
        throw new RuntimeException(cryptException);
      }
    }
    if (this.aznUrl != null) {
      response.setMetadata(OAuth2ResponseParams.APPROVAL_URL, this.aznUrl);
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

  /**
   * Get the state we will return to the client.
   */
  public OAuth2ClientState getNewClientState() {
    return this.newClientState;
  }

  public String getAznUrl() {
    return this.aznUrl;
  }

  /**
   * Set the authorization URL we will return to the client.
   */
  public void setAznUrl(final String aznUrl) {
    this.aznUrl = aznUrl;
  }

  public boolean sendTraceToClient() {
    return this.sendTraceToClient;
  }

  public void setSendTraceToClient(final boolean sendTraceToClient) {
    this.sendTraceToClient = sendTraceToClient;
  }
}
