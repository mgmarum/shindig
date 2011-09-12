package org.apache.shindig.gadgets.oauth2.sample;

import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.apache.commons.codec.binary.Base64;
import org.apache.shindig.auth.SecurityToken;
import org.apache.shindig.common.uri.Uri;
import org.apache.shindig.gadgets.GadgetException;
import org.apache.shindig.gadgets.http.HttpFetcher;
import org.apache.shindig.gadgets.http.HttpRequest;
import org.apache.shindig.gadgets.http.HttpResponse;
import org.apache.shindig.gadgets.oauth2.OAuth2Accessor;
import org.apache.shindig.gadgets.oauth2.OAuth2CallbackState;
import org.apache.shindig.gadgets.oauth2.OAuth2Client;
import org.apache.shindig.gadgets.oauth2.OAuth2Client.Flow;
import org.apache.shindig.gadgets.oauth2.OAuth2Error;
import org.apache.shindig.gadgets.oauth2.OAuth2Message;
import org.apache.shindig.gadgets.oauth2.OAuth2RequestException;
import org.apache.shindig.gadgets.oauth2.OAuth2StateChangeListener;
import org.apache.shindig.gadgets.oauth2.OAuth2Store;
import org.apache.shindig.gadgets.oauth2.OAuth2Token;
import org.apache.shindig.gadgets.oauth2.OAuth2Utils;
import org.apache.shindig.gadgets.oauth2.persistence.OAuth2EncryptionException;
import org.json.JSONException;
import org.json.JSONObject;

public class OAuth2CallbackStateImpl implements OAuth2CallbackState {

  /**
   * 
   */
  private static final long serialVersionUID = 1L;

  private final Integer stateKey;
  private final Flow flow;
  private final SecurityToken securityToken;
  private final Set<OAuth2StateChangeListener> listeners;
  private State state;
  private String authorizationCode;
  private String realCallbackUrl;
  private String realErrorCallbackUrl;
  private final OAuth2Accessor accessor;
  private final HttpFetcher fetcher;
  private final OAuth2Client client;

  private static int STATE_KEY_COUNT = 0;

  public OAuth2CallbackStateImpl(final OAuth2Accessor accessor, final OAuth2Client client,
      final Flow flow, final SecurityToken securityToken, final HttpFetcher fetcher) {
    this.state = State.NOT_STARTED;
    OAuth2CallbackStateImpl.STATE_KEY_COUNT++;
    this.stateKey = new Integer(OAuth2CallbackStateImpl.STATE_KEY_COUNT);
    this.flow = flow;
    this.securityToken = securityToken;
    this.listeners = new HashSet<OAuth2StateChangeListener>(1);
    this.accessor = accessor;
    this.fetcher = fetcher;
    this.client = client;
  }

  public void invalidate() {
    this.changeState(State.UNKNOWN);
    this.authorizationCode = null;
    this.realCallbackUrl = null;
    this.realErrorCallbackUrl = null;
    this.listeners.clear();
  }

  public Integer getStateKey() {
    return this.stateKey;
  }

  public Flow getFlow() {
    return this.flow;
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

  public String getAuthorizationCode() {
    return this.authorizationCode;
  }

  public OAuth2Error setAuthorizationCode(final String authorizationCode)
      throws OAuth2RequestException {
    this.authorizationCode = authorizationCode;
    final String accessTokenUrl = this.buildAccessTokenUrl();
    HttpResponse response = null;
    final HttpRequest request = new HttpRequest(Uri.parse(accessTokenUrl));
    request.setMethod("POST");
    request.setHeader("Content-Type", "application/x-www-form-urlencoded; charset=utf-8");

    final String clientId = this.client.getKey();
    final String secret = this.client.getSecret();

    request.setHeader("client_id", clientId);
    request.setHeader("client_secret", secret);
    request.setParam("client_id", clientId);
    request.setParam("client_secret", secret);

    final String authString = clientId + ":" + secret;
    final byte[] authBytes = Base64.encodeBase64(authString.getBytes());
    request.setHeader("Auhtorization", "Basic: " + new String(authBytes));

    try {
      final byte[] body = this.getAuthorizationBody(this.accessor).getBytes("UTF-8");
      request.setPostBody(body);

      this.changeState(State.ACCESS_REQUESTED);

      response = this.fetcher.fetch(request);
      if (response == null) {
        throw new OAuth2RequestException(OAuth2Error.MISSING_SERVER_RESPONSE);
      }

      final int responseCode = response.getHttpStatusCode();
      if (responseCode != 200) {
        return OAuth2CallbackStateImpl.parseError(response);
      }

      final String contentType = response.getHeader("Content-Type");
      final String responseString = response.getResponseAsString();
      final OAuth2Message msg = new OAuth2Message();

      if (contentType.startsWith("text/plain")) {
        // Facebook does this
        msg.parseQuery("?" + responseString);
      } else if (contentType.startsWith("application/json")) {
        // Google does this
        final JSONObject responseJson = new JSONObject(responseString);
        msg.parseJSON(responseJson);
      } else {
        return OAuth2Error.UNKNOWN_PROBLEM;
      }

      final OAuth2Error error = msg.getError();
      if (error == null) {
        final String accessToken = msg.getAccessToken();
        final String refreshToken = msg.getRefreshToken();
        final String expiresIn = msg.getExpiresIn();
        final String tokenType = msg.getTokenType();
        final String providerName = this.client.getProviderName();
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
          storedAccessToken.setProviderName(providerName);
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
          storedRefreshToken.setProviderName(providerName);
          storedRefreshToken.setScope(scope);
          storedRefreshToken.setSecret(refreshToken);
          storedRefreshToken.setTokenType(tokenType);
          storedRefreshToken.setType(OAuth2Token.Type.REFRESH);
          storedRefreshToken.setUser(user);
          store.setToken(storedRefreshToken);
        }

        this.changeState(State.ACCESS_SUCCEEDED);
      } else {
        throw new RuntimeException("@@@ TODO ARC, implement access token error handling");
      }
      // TODO ARC make this exceptions better
    } catch (final GadgetException e) {
      throw new OAuth2RequestException(OAuth2Error.MISSING_SERVER_RESPONSE, "", e);
    } catch (final UnsupportedEncodingException e) {
      throw new OAuth2RequestException(OAuth2Error.MISSING_SERVER_RESPONSE, "", e);
    } catch (final JSONException e) {
      throw new OAuth2RequestException(OAuth2Error.MISSING_SERVER_RESPONSE, "", e);
    } catch (final OAuth2EncryptionException e) {
      throw new OAuth2RequestException(OAuth2Error.MISSING_SERVER_RESPONSE, "", e);
    }

    return null;
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
      if (OAuth2CallbackStateImpl.class.isInstance(other)) {
        return this.hashCode() == other.hashCode();
      }
    }

    return false;
  }

  private String buildAccessTokenUrl() throws OAuth2RequestException {
    final String accessTokenUrl = this.accessor.getProvider().getTokenUrl();
    if (accessTokenUrl == null) {
      throw new OAuth2RequestException(OAuth2Error.BAD_OAUTH_TOKEN_URL, "token");
    }

    final String completeAccessTokenUrl = this.getCompleteAuthorizationUrl(accessTokenUrl);

    return completeAccessTokenUrl;
  }

  private String getCompleteAuthorizationUrl(final String accessTokenUrl)
      throws OAuth2RequestException {
    final String ret = OAuth2Utils.buildUrl(accessTokenUrl, null, null);

    return ret;
  }

  private String getAuthorizationBody(final OAuth2Accessor accessor) throws OAuth2RequestException {
    String ret = "";

    String type = "code";

    switch (accessor.getFlow()) {
    case CODE:
      type = "authorization_code";
      break;
    case TOKEN:
      type = "token";
      break;
    default:
      throw new OAuth2RequestException(OAuth2Error.MISSING_OAUTH_PARAMETER,
          "There is no type parameter");
    }

    final Map<String, String> queryParams = new HashMap<String, String>(5);
    queryParams.put("grant_type", type);
    queryParams.put("code", this.getAuthorizationCode());
    queryParams.put("redirect_uri", accessor.getClient().getRedirectUri());

    final String clientId = this.client.getKey();
    final String secret = this.client.getSecret();
    queryParams.put("client_id", clientId);
    queryParams.put("client_secret", secret);

    ret = OAuth2Utils.buildUrl(ret, queryParams, null);

    if ((ret.startsWith("?")) || (ret.startsWith("&"))) {
      ret = ret.substring(1);
    }

    return ret;
  }

  public OAuth2Error refreshToken() throws OAuth2RequestException {
    final String refershTokenUrl = this.buildRefreshTokenUrl();

    HttpResponse response = null;
    final HttpRequest request = new HttpRequest(Uri.parse(refershTokenUrl));
    request.setMethod("POST");
    request.setHeader("Content-Type", "application/x-www-form-urlencoded; charset=utf-8");

    final String clientId = this.client.getKey();
    final String secret = this.client.getSecret();

    request.setHeader("client_id", clientId);
    request.setHeader("client_secret", secret);
    request.setParam("client_id", clientId);
    request.setParam("client_secret", secret);

    final String authString = clientId + ":" + secret;
    final byte[] authBytes = Base64.encodeBase64(authString.getBytes());
    request.setHeader("Auhtorization", "Basic: " + new String(authBytes));

    try {
      final byte[] body = this.getRefreshBody(this.accessor).getBytes("UTF-8");
      request.setPostBody(body);

      this.changeState(State.REFRESH_REQUESTED);

      response = this.fetcher.fetch(request);
      if (response == null) {
        throw new OAuth2RequestException(OAuth2Error.MISSING_SERVER_RESPONSE);
      }
      final OAuth2Message msg = new OAuth2Message();
      final JSONObject responseJson = new JSONObject(response.getResponseAsString());
      msg.parseJSON(responseJson);
      final OAuth2Error error = msg.getError();
      if (error == null) {
        final String accessToken = msg.getAccessToken();
        final String refreshToken = msg.getRefreshToken();
        final String expiresIn = msg.getExpiresIn();
        final String tokenType = msg.getTokenType();
        final String providerName = this.client.getProviderName();
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
          storedAccessToken.setProviderName(providerName);
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
          storedRefreshToken.setProviderName(providerName);
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
    } catch (final OAuth2EncryptionException e) {
      throw new OAuth2RequestException(OAuth2Error.MISSING_SERVER_RESPONSE, "", e);
    }

    return null;
  }

  private String buildRefreshTokenUrl() throws OAuth2RequestException {
    final String refreshUrl = this.accessor.getProvider().getTokenUrl();
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

    final String clientId = this.client.getKey();
    final String secret = this.client.getSecret();
    queryParams.put("client_id", clientId);
    queryParams.put("client_secret", secret);

    ret = OAuth2Utils.buildUrl(ret, queryParams, null);

    if ((ret.startsWith("?")) || (ret.startsWith("&"))) {
      ret = ret.substring(1);
    }

    return ret;
  }

  private static OAuth2Error parseError(final HttpResponse response) {
    return OAuth2Error.UNKNOWN_PROBLEM; // TODO ARC, improve error response
  }
}
