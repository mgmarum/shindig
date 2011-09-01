/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */
package org.apache.shindig.gadgets.oauth2;

import java.util.Map;

import org.apache.shindig.common.crypto.BlobCrypter;
import org.apache.shindig.common.crypto.BlobCrypterException;

import com.google.common.collect.Maps;

/**
 * Class to handle OAuth fetcher state stored client side. The state is stored
 * as a signed, encrypted, time stamped blob.
 */

// NO IBM CONFIDENTIAL CODE OR INFORMATION!

public class OAuth2ClientState {
  /**
   * Maximum age for our client state; if this is exceeded we start over. One
   * hour is a fairly arbitrary time limit here.
   */
  private static final int CLIENT_STATE_MAX_AGE_SECS = 3600;

  // Our client state is encrypted key/value pairs. These are the key names.
  private static final String REQ_TOKEN_KEY = "r";
  private static final String REQ_TOKEN_SECRET_KEY = "rs";
  private static final String ACCESS_TOKEN_KEY = "a";
  private static final String ACCESS_TOKEN_SECRET_KEY = "as";
  private static final String OWNER_KEY = "o";
  private static final String SESSION_HANDLE_KEY = "sh";
  private static final String ACCESS_TOKEN_EXPIRATION_KEY = "e";

  /** Name/value pairs */
  private final Map<String, String> state;

  /** Crypter to use when sending these to the client */
  private final BlobCrypter crypter;

  /**
   * Create a new, empty client state blob.
   * 
   * @param crypter
   */
  public OAuth2ClientState(final BlobCrypter crypter) {
    this.state = Maps.newHashMap();
    this.crypter = crypter;
  }

  /**
   * Initialize client state based on an encrypted blob passed by the client.
   * 
   * @param crypter
   * @param stateBlob
   */
  public OAuth2ClientState(final BlobCrypter crypter, final String stateBlob) {
    this.crypter = crypter;
    Map<String, String> state = null;
    if (stateBlob != null) {
      try {
        state = crypter.unwrap(stateBlob, OAuth2ClientState.CLIENT_STATE_MAX_AGE_SECS);
      } catch (final BlobCrypterException e) {
        // Probably too old, pretend we never saw it at all.
      }
    }
    if (state == null) {
      state = Maps.newHashMap();
    }
    this.state = state;
  }

  /**
   * @return true if there is no state to store with the client.
   */
  public boolean isEmpty() {
    // Might contain just a timestamp
    return (this.state.isEmpty() || ((this.state.size() == 1) && this.state.containsKey("t")));
  }

  /**
   * @return an encrypted blob of state to store with the client.
   * @throws BlobCrypterException
   */
  public String getEncryptedState() throws BlobCrypterException {
    return this.crypter.wrap(this.state);
  }

  /**
   * OAuth request token
   */
  public String getRequestToken() {
    return this.state.get(OAuth2ClientState.REQ_TOKEN_KEY);
  }

  public void setRequestToken(final String requestToken) {
    this.setNullCheck(OAuth2ClientState.REQ_TOKEN_KEY, requestToken);
  }

  /**
   * OAuth request token secret
   */
  public String getRequestTokenSecret() {
    return this.state.get(OAuth2ClientState.REQ_TOKEN_SECRET_KEY);
  }

  public void setRequestTokenSecret(final String requestTokenSecret) {
    this.setNullCheck(OAuth2ClientState.REQ_TOKEN_SECRET_KEY, requestTokenSecret);
  }

  /**
   * OAuth access token.
   */
  public String getAccessToken() {
    return this.state.get(OAuth2ClientState.ACCESS_TOKEN_KEY);
  }

  public void setAccessToken(final String accessToken) {
    this.setNullCheck(OAuth2ClientState.ACCESS_TOKEN_KEY, accessToken);
  }

  /**
   * OAuth access token secret.
   */
  public String getAccessTokenSecret() {
    return this.state.get(OAuth2ClientState.ACCESS_TOKEN_SECRET_KEY);
  }

  public void setAccessTokenSecret(final String accessTokenSecret) {
    this.setNullCheck(OAuth2ClientState.ACCESS_TOKEN_SECRET_KEY, accessTokenSecret);
  }

  /**
   * Session handle
   * (http://oauth.googlecode.com/svn/spec/ext/session/1.0/drafts/1/spec.html)
   */
  public String getSessionHandle() {
    return this.state.get(OAuth2ClientState.SESSION_HANDLE_KEY);
  }

  public void setSessionHandle(final String sessionHandle) {
    this.setNullCheck(OAuth2ClientState.SESSION_HANDLE_KEY, sessionHandle);
  }

  /**
   * Expiration of access token
   * (http://oauth.googlecode.com/svn/spec/ext/session/1.0/drafts/1/spec.html)
   */
  public long getTokenExpireMillis() {
    final String expiration = this.state.get(OAuth2ClientState.ACCESS_TOKEN_EXPIRATION_KEY);
    if (expiration == null) {
      return 0;
    }
    return Long.parseLong(expiration);
  }

  public void setTokenExpireMillis(final long expirationMillis) {
    this.setNullCheck(OAuth2ClientState.ACCESS_TOKEN_EXPIRATION_KEY,
        Long.toString(expirationMillis));
  }

  /**
   * Owner of the OAuth token.
   */
  public String getOwner() {
    return this.state.get(OAuth2ClientState.OWNER_KEY);
  }

  public void setOwner(final String owner) {
    this.setNullCheck(OAuth2ClientState.OWNER_KEY, owner);
  }

  private void setNullCheck(final String key, final String value) {
    if (value == null) {
      this.state.remove(key);
    } else {
      this.state.put(key, value);
    }
  }
}
