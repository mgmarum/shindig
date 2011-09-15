package org.apache.shindig.gadgets.oauth2;

import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.shindig.auth.SecurityToken;
import org.apache.shindig.common.uri.Uri;
import org.apache.shindig.gadgets.GadgetException;
import org.apache.shindig.gadgets.http.HttpFetcher;
import org.apache.shindig.gadgets.http.HttpRequest;
import org.apache.shindig.gadgets.http.HttpResponse;
import org.json.JSONException;
import org.json.JSONObject;

import com.google.inject.Inject;
import com.google.inject.Provider;

public class OAuth2CallbackState implements Serializable {

  public OAuth2Accessor getAccessor() {
    return this.accessor;
  }

  public HttpFetcher getFetcher() {
    return this.fetcher;
  }

  public OAuth2Client getClient() {
    return this.client;
  }

  public Provider<OAuth2Message> getOauth2MessageProvider() {
    return this.oauth2MessageProvider;
  }

  public List<OAuth2ClientAuthenticationHandler> getAuthenticationHandlers() {
    return this.authenticationHandlers;
  }

  public List<OAuth2GrantTypeHandler> getGrantTypeHandlers() {
    return this.grantTypeHandlers;
  }

  /**
   * 
   */
  private static final long serialVersionUID = 1L;

  public enum State {
    UNKNOWN, NOT_STARTED, AUTHORIZATION_REQUESTED, AUTHORIZATION_SUCCEEDED, AUTHORIZATION_FAILED, ACCESS_REQUESTED, ACCESS_FAILED, ACCESS_SUCCEEDED, REFRESH_REQUESTED, REFERESH_FAILED, REFRESH_SUCCEEDED
  }

  private final Integer stateKey;
  private final String grantType;
  private final SecurityToken securityToken;
  private final Set<OAuth2StateChangeListener> listeners;
  private State state;
  private String realCallbackUrl;
  private String realErrorCallbackUrl;
  private final OAuth2Accessor accessor;
  private final HttpFetcher fetcher;
  private final OAuth2Client client;
  private final Provider<OAuth2Message> oauth2MessageProvider;
  private final List<OAuth2ClientAuthenticationHandler> authenticationHandlers;
  private final List<OAuth2GrantTypeHandler> grantTypeHandlers;

  private static int STATE_KEY_COUNT = 0;

  @Inject
  public OAuth2CallbackState(final OAuth2Accessor accessor, final OAuth2Client client,
      final String grantType, final SecurityToken securityToken, final HttpFetcher fetcher,
      final Provider<OAuth2Message> oauth2MessageProvider,
      final List<OAuth2ClientAuthenticationHandler> authenticationHandlers,
      final List<OAuth2GrantTypeHandler> grantTypeHandlers) {
    this.state = State.NOT_STARTED;
    OAuth2CallbackState.STATE_KEY_COUNT++;
    this.stateKey = new Integer(OAuth2CallbackState.STATE_KEY_COUNT);
    this.grantType = grantType;
    this.securityToken = securityToken;
    this.listeners = new HashSet<OAuth2StateChangeListener>(1);
    this.accessor = accessor;
    this.fetcher = fetcher;
    this.client = client;
    this.oauth2MessageProvider = oauth2MessageProvider;
    this.authenticationHandlers = authenticationHandlers;
    this.grantTypeHandlers = grantTypeHandlers;
  }

  public void invalidate() {
    this.changeState(State.UNKNOWN);
    this.realCallbackUrl = null;
    this.realErrorCallbackUrl = null;
    this.listeners.clear();
  }

  public Integer getStateKey() {
    return this.stateKey;
  }

  public String getGrantType() {
    return this.grantType;
  }

  public SecurityToken getSecurityToken() {
    return this.securityToken;
  }

  public Set<OAuth2StateChangeListener> getListeners() {
    return this.listeners;
  }

  public State getState() {
    return this.state;
  }

  public void addOAuth2StateChangeListener(final OAuth2StateChangeListener listener) {
    this.listeners.add(listener);
  }

  public void setState(final State state) {
    this.changeState(state);
  }

  public boolean changeState(final State newState) {
    // TODO ARC, should we have state change validation and listener veto?
    synchronized (this) {
      final State oldState = this.state;
      for (final OAuth2StateChangeListener listener : this.listeners) {
        listener.stateChange(this, oldState, newState);
      }
      this.state = newState;
    }

    return true;
  }

  public String getRealCallbackUrl() {
    return this.realCallbackUrl;
  }

  public void setRealCallbackUrl(final String realCallbackUrl) {
    this.realCallbackUrl = realCallbackUrl;
  }

  public String getRealErrorCallbackUrl() {
    return this.realErrorCallbackUrl;
  }

  public void setRealErrorCallbackUrl(final String realErrorCallbackUrl) {
    this.realErrorCallbackUrl = realErrorCallbackUrl;
  }

  @Override
  public int hashCode() {
    return this.stateKey.intValue();
  }

  @Override
  public boolean equals(final Object other) {
    if (other != null) {
      if (OAuth2CallbackState.class.isInstance(other)) {
        return this.hashCode() == other.hashCode();
      }
    }

    return false;
  }

  public OAuth2Error refreshToken() throws OAuth2RequestException {
    final String refershTokenUrl = this.buildRefreshTokenUrl();

    HttpResponse response = null;
    final HttpRequest request = new HttpRequest(Uri.parse(refershTokenUrl));
    request.setMethod("POST");
    request.setHeader("Content-Type", "application/x-www-form-urlencoded; charset=utf-8");

    final String clientId = this.client.getClientId();
    final String secret = this.client.getClientSecret();

    request.setHeader(OAuth2Message.CLIENT_ID, clientId);
    request.setHeader(OAuth2Message.CLIENT_SECRET, secret);
    request.setParam(OAuth2Message.CLIENT_ID, clientId);
    request.setParam(OAuth2Message.CLIENT_SECRET, secret);

    for (final OAuth2ClientAuthenticationHandler authenticationHandler : this.authenticationHandlers) {
      if (authenticationHandler.geClientAuthenticationType().equalsIgnoreCase(
          this.client.getClientAuthenticationType())) {
        authenticationHandler.addOAuth2Authentication(request, this.accessor);
      }
    }

    try {
      final byte[] body = this.getRefreshBody(this.accessor).getBytes("UTF-8");
      request.setPostBody(body);

      this.changeState(State.REFRESH_REQUESTED);

      response = this.fetcher.fetch(request);
      if (response == null) {
        throw new OAuth2RequestException(OAuth2Error.MISSING_SERVER_RESPONSE);
      }
      final OAuth2Message msg = this.oauth2MessageProvider.get();

      final JSONObject responseJson = new JSONObject(response.getResponseAsString());
      msg.parseJSON(responseJson.toString());
      final OAuth2Error error = msg.getError();
      if (error == null) {
        final String accessToken = msg.getAccessToken();
        final String refreshToken = msg.getRefreshToken();
        final String expiresIn = msg.getExpiresIn();
        final String tokenType = msg.getTokenType();
        final String serviceName = this.client.getServiceName();
        final String gadgetUri = this.client.getGadgetUri();
        final String scope = this.accessor.getScope();
        final String user = this.securityToken.getViewerId();

        final OAuth2Store store = this.accessor.getStore();

        if (accessToken != null) {
          final OAuth2Token storedAccessToken = store.createToken();
          if (expiresIn != null) {
            storedAccessToken.setExpiresIn(Integer.decode(expiresIn));
          } else {
            storedAccessToken.setExpiresIn(0);
          }
          storedAccessToken.setGadgetUri(gadgetUri);
          storedAccessToken.setServiceName(serviceName);
          storedAccessToken.setScope(scope);
          storedAccessToken.setSecret(accessToken);
          storedAccessToken.setTokenType(tokenType);
          storedAccessToken.setType(OAuth2Token.Type.ACCESS);
          storedAccessToken.setUser(user);
          store.setToken(storedAccessToken);
        }

        if (refreshToken != null) {
          final OAuth2Token storedRefreshToken = store.createToken();
          storedRefreshToken.setExpiresIn(0);
          storedRefreshToken.setGadgetUri(gadgetUri);
          storedRefreshToken.setServiceName(serviceName);
          storedRefreshToken.setScope(scope);
          storedRefreshToken.setSecret(refreshToken);
          storedRefreshToken.setTokenType(tokenType);
          storedRefreshToken.setType(OAuth2Token.Type.REFRESH);
          storedRefreshToken.setUser(user);
          store.setToken(storedRefreshToken);
        }

        this.changeState(State.REFRESH_SUCCEEDED);
      } else {
        throw new RuntimeException("@@@ TODO ARC, implement refresh token error handling");
      }
      // TODO ARC make this exceptions better
    } catch (final GadgetException e) {
      throw new OAuth2RequestException(OAuth2Error.MISSING_SERVER_RESPONSE, "", e);
    } catch (final UnsupportedEncodingException e) {
      throw new OAuth2RequestException(OAuth2Error.MISSING_SERVER_RESPONSE, "", e);
    } catch (final JSONException e) {
      throw new OAuth2RequestException(OAuth2Error.MISSING_SERVER_RESPONSE, "", e);
    }

    return null;
  }

  private String buildRefreshTokenUrl() throws OAuth2RequestException {
    final String refreshUrl = this.client.getTokenUrl();
    if (refreshUrl == null) {
      throw new OAuth2RequestException(OAuth2Error.BAD_OAUTH_TOKEN_URL, "token");
    }

    final String completeRefershTokenUrl = this.getCompleteRefreshUrl(refreshUrl);

    return completeRefershTokenUrl;
  }

  private String getCompleteRefreshUrl(final String refreshUrl) throws OAuth2RequestException {
    final String ret = OAuth2Utils.buildUrl(refreshUrl, null, null);

    return ret;
  }

  private String getRefreshBody(final OAuth2Accessor accessor) throws OAuth2RequestException {
    String ret = "";

    final Map<String, String> queryParams = new HashMap<String, String>(5);
    queryParams.put("grant_type", OAuth2Message.REFRESH_TOKEN);
    queryParams.put(OAuth2Message.REFRESH_TOKEN, this.accessor.getRefreshToken().getSecret());
    if ((accessor.getScope() != null) && (accessor.getScope().length() > 0)) {
      queryParams.put("scope", accessor.getScope());
    }

    final String clientId = this.client.getClientId();
    final String secret = this.client.getClientSecret();
    queryParams.put("client_id", clientId);
    queryParams.put("client_secret", secret);

    ret = OAuth2Utils.buildUrl(ret, queryParams, null);

    if ((ret.startsWith("?")) || (ret.startsWith("&"))) {
      ret = ret.substring(1);
    }

    return ret;
  }
}
