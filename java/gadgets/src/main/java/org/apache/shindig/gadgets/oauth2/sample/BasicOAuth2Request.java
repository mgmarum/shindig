/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */
package org.apache.shindig.gadgets.oauth2.sample;

import java.util.List;

import net.oauth.OAuth.Parameter;

import org.apache.shindig.common.logging.i18n.MessageKeys;
import org.apache.shindig.common.uri.Uri;
import org.apache.shindig.gadgets.GadgetException;
import org.apache.shindig.gadgets.http.HttpFetcher;
import org.apache.shindig.gadgets.http.HttpRequest;
import org.apache.shindig.gadgets.http.HttpResponse;
import org.apache.shindig.gadgets.http.HttpResponseBuilder;
import org.apache.shindig.gadgets.oauth2.OAuth2Accessor;
import org.apache.shindig.gadgets.oauth2.OAuth2Error;
import org.apache.shindig.gadgets.oauth2.OAuth2FetcherConfig;
import org.apache.shindig.gadgets.oauth2.OAuth2Message;
import org.apache.shindig.gadgets.oauth2.OAuth2ProtocolException;
import org.apache.shindig.gadgets.oauth2.OAuth2Request;
import org.apache.shindig.gadgets.oauth2.OAuth2RequestException;
import org.apache.shindig.gadgets.oauth2.OAuth2ResponseParams;

import com.google.common.collect.Lists;

// NO IBM CONFIDENTIAL CODE OR INFORMATION!

public class BasicOAuth2Request implements OAuth2Request {
  // class name for logging purpose
  private static final String classname = BasicOAuth2Request.class.getName();

  protected final OAuth2FetcherConfig fetcherConfig;

  private final HttpFetcher fetcher;

  protected HttpRequest realRequest;

  protected OAuth2ResponseParams responseParams;

  protected OAuth2Accessor accessor;

  /**
   * @param fetcherConfig
   *          configuration options for the fetcher
   * @param fetcher
   *          fetcher to use for actually making requests
   */
  public BasicOAuth2Request(final OAuth2FetcherConfig fetcherConfig, final HttpFetcher fetcher) {
    this.fetcherConfig = fetcherConfig;
    this.fetcher = fetcher;
  }

  public HttpResponse fetch(final HttpRequest request) {
    this.realRequest = request;
    this.responseParams = new OAuth2ResponseParams(request.getSecurityToken(), request,
        this.fetcherConfig.getStateCrypter());
    try {
      return this.fetchNoThrow();
    } catch (final RuntimeException e) {
      // We log here to record the request/response pairs that created the
      // failure.
      this.responseParams.logDetailedWarning(BasicOAuth2Request.classname, "fetch",
          MessageKeys.OAUTH_FETCH_UNEXPECTED_ERROR, e);
      throw e;
    }
  }

  private HttpResponse fetchNoThrow() {
    HttpResponseBuilder response = null;
    try {
      this.accessor = this.fetcherConfig.getTokenStore().getOAuth2Accessor(
          this.realRequest.getSecurityToken(), this.realRequest.getOAuth2Arguments(),
          this.fetcherConfig);
      response = this.fetchWithRetry();
    } catch (final OAuth2RequestException e) {
      e.printStackTrace(); // TODO ARC
      // No data for us.
      if (OAuth2Error.UNAUTHENTICATED.name().equals(e.getError())) {
        this.responseParams.logDetailedInfo(BasicOAuth2Request.classname, "fetchNoThrow",
            MessageKeys.UNAUTHENTICATED_OAUTH, e);
      } else if (OAuth2Error.BAD_OAUTH_TOKEN_URL.name().equals(e.getError())) {
        this.responseParams.logDetailedInfo(BasicOAuth2Request.classname, "fetchNoThrow",
            MessageKeys.INVALID_OAUTH, e);
      } else {
        this.responseParams.logDetailedWarning(BasicOAuth2Request.classname, "fetchNoThrow",
            MessageKeys.OAUTH_FETCH_FATAL_ERROR, e);
      }
      this.responseParams.setSendTraceToClient(true);
      response = new HttpResponseBuilder().setHttpStatusCode(HttpResponse.SC_FORBIDDEN)
          .setStrictNoCache();
      this.responseParams.addToResponse(response, e);
      return response.create();
    }

    // OK, got some data back, annotate it as necessary.
    if (response.getHttpStatusCode() >= 400) {
      this.responseParams.logDetailedWarning(BasicOAuth2Request.classname, "fetchNoThrow",
          MessageKeys.OAUTH_FETCH_FATAL_ERROR);

      this.responseParams.setSendTraceToClient(true);
    } else if ((this.responseParams.getAznUrl() != null) && this.responseParams.sawErrorResponse()) {
      this.responseParams.logDetailedWarning(BasicOAuth2Request.classname, "fetchNoThrow",
          MessageKeys.OAUTH_FETCH_ERROR_REPROMPT);
      this.responseParams.setSendTraceToClient(true);
    }

    this.responseParams.addToResponse(response, null);
    return response.create();
  }

  private HttpResponseBuilder fetchWithRetry() throws OAuth2RequestException {
    int attempts = 0;
    boolean retry;
    HttpResponseBuilder response = null;
    do {
      retry = false;
      ++attempts;
      try {
        response = this.attemptFetch();
      } catch (final OAuth2ProtocolException pe) {
        retry = this.handleProtocolException(pe, attempts);
        if (!retry) {
          if (pe.getProblemCode() != null) {
            throw new OAuth2RequestException(pe.getProblemCode(),
                "Service provider rejected request", pe);
          } else {
            throw new OAuth2RequestException(OAuth2Error.UNKNOWN_PROBLEM,
                "Service provider rejected request", pe);
          }
        }
      }
    } while (retry);
    return response;
  }

  private HttpResponseBuilder attemptFetch() throws OAuth2RequestException, OAuth2ProtocolException {
    if (this.needAuthorization()) {
      this.checkCanAuthorize();
      this.fetchAuthorizationGrant();
    }
    // // This is section 6.2 of the OAuth spec.
    // // buildClientApprovalState();
    // // This is section 4.1.1 of OAuth2.0 spec
    // buildAznUrl();
    // // break out of the content fetching chain, we need permission from
    // // the user to do this
    // return new
    // HttpResponseBuilder().setHttpStatusCode(HttpResponse.SC_OK).setStrictNoCache();
    // } else if (needAccessToken()) {
    // // This is section 4.1.3 of the OAuth2.0 spec
    // checkCanApprove();
    // getAccessToken();
    // saveAccessToken();
    // buildClientAccessState();
    // }
    return this.fetchData();
  }

  private void checkCanAuthorize() throws OAuth2RequestException {
    // TODO ARC
  }

  private boolean needAuthorization() {
    boolean ret = true;
    if (this.accessor.getAccessToken() != null) {
      ret = false;
    }
    return ret;
  }

  private void fetchAuthorizationGrant() throws OAuth2RequestException, OAuth2ProtocolException {
    final HttpRequest request = this.createAuthorizationRequest(this.accessor);

    final List<Parameter> requestTokenParams = Lists.newArrayList();

    final HttpRequest signed = this.sanitizeAndSign(request, requestTokenParams, true);

    final OAuth2Message reply = this.sendOAuthMessage(signed);

    this.accessor.setAuthorizationCode(reply.getAuthorizationCode());
  }

  private HttpRequest createAuthorizationRequest(final OAuth2Accessor accessor)
      throws OAuth2RequestException {
    final String authorizationUrl = accessor.getAuthorizationUrl();
    if (authorizationUrl == null) {
      throw new OAuth2RequestException(OAuth2Error.BAD_OAUTH_TOKEN_URL, "authorizationUrl is null");
    }

    final String completeAuthorizationUrl = this.getCompleteAuthorizationUrl(authorizationUrl,
        accessor);

    final HttpRequest request = new HttpRequest(Uri.parse(completeAuthorizationUrl));
    request.setMethod(accessor.getMethod().name());
    return request;
  }

  private String getCompleteAuthorizationUrl(final String authorizationUrl,
      final OAuth2Accessor accessor) {
    String ret = authorizationUrl;
    String type = "code";
    switch (accessor.getAuthorizationType()) {
    case AUTHORIZATION_CODE:
      type = "code";
    }
    ret = ret + "?response_type=" + type;
    ret = ret + "&client_id=" + accessor.getClientId();
    ret = ret + "&redirect_uri=" + accessor.getRedirectUri();
    ret = ret + "&state=" + accessor.getState();
    final String scope = accessor.getScope();
    if (scope != null) {
      ret = ret + "&scope=" + accessor.getScope();
    }

    return ret;
  }

  private OAuth2Message sendOAuthMessage(final HttpRequest request) throws OAuth2RequestException,
      OAuth2ProtocolException {
    System.err.println("@@@ request = " + request);
    System.err.println("@@@ request.getMethod() = " + request.getMethod());
    System.err.println("@@@ request.getAuthType() = " + request.getAuthType());
    System.err.println("@@@ request.getHeaders() = " + request.getHeaders());
    System.err.println("@@@ request.getParams() = " + request.getParams());

    final HttpResponse response = this.fetchFromServer(request);

    System.err.println("@@@ response.getResponseAsString() = " + response.getHttpStatusCode()
        + "  " + response.getResponseAsString());

    this.checkForProtocolProblem(response);

    // reply.addParameters(OAuth.decodeForm(response.getResponseAsString()));
    // reply = parseAuthHeader(reply, response);
    // if (OAuthUtil.getParameter(reply, OAuth.OAUTH_TOKEN) == null) {
    // throw new OAuthRequestException(OAuthError.MISSING_OAUTH_PARAMETER,
    // OAuth.OAUTH_TOKEN);
    // }
    // if (OAuthUtil.getParameter(reply, OAuth.OAUTH_TOKEN_SECRET) == null) {
    // throw new OAuthRequestException(OAuthError.MISSING_OAUTH_PARAMETER,
    // OAuth.OAUTH_TOKEN_SECRET);
    // }

    return new OAuth2Message();
  }

  private HttpResponseBuilder fetchData() throws OAuth2RequestException, OAuth2ProtocolException {
    HttpResponseBuilder builder = null;

    final HttpResponse response = this.fetchFromServer(this.realRequest);

    this.checkForProtocolProblem(response);
    builder = new HttpResponseBuilder(response);

    return builder;
  }

  private HttpResponse fetchFromServer(final HttpRequest request) throws OAuth2RequestException {
    HttpResponse response = null;
    try {
      response = this.fetcher.fetch(request);
      if (response == null) {
        throw new OAuth2RequestException(OAuth2Error.MISSING_SERVER_RESPONSE);
      }
      return response;
    } catch (final GadgetException e) {
      throw new OAuth2RequestException(OAuth2Error.MISSING_SERVER_RESPONSE, "", e);
    } finally {
      this.responseParams.addRequestTrace(request, response);
    }
  }

  private void checkForProtocolProblem(final HttpResponse response) throws OAuth2ProtocolException {
  }

  private boolean handleProtocolException(final OAuth2ProtocolException pe, final int attempts)
      throws OAuth2RequestException {
    return false;
  }

  public HttpRequest sanitizeAndSign(final HttpRequest arg0, final List<Parameter> arg1,
      final boolean arg2) throws OAuth2RequestException {
    return arg0;
  }

}