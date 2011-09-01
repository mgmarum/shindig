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
 * Handles state passed on the OAuth callback URL.
 * 
 * TODO: there's probably an abstract superclass that can be reused by
 * OAuthClientState and this class.
 */

// NO IBM CONFIDENTIAL CODE OR INFORMATION!

public class OAuth2CallbackState {

  private static final int CALLBACK_STATE_MAX_AGE_SECS = 600;

  private static final String REAL_CALLBACK_URL_KEY = "u";

  private final BlobCrypter crypter;
  private final Map<String, String> state;

  public OAuth2CallbackState(final BlobCrypter crypter) {
    this.crypter = crypter;
    this.state = Maps.newHashMap();
  }

  public OAuth2CallbackState(final BlobCrypter crypter, final String stateBlob) {
    this.crypter = crypter;
    Map<String, String> state = Maps.newHashMap();
    if (stateBlob != null) {
      try {
        state = crypter.unwrap(stateBlob, OAuth2CallbackState.CALLBACK_STATE_MAX_AGE_SECS);
      } catch (final BlobCrypterException e) {
        // Too old, or corrupt. Ignore it.
      }
    }
    if (state == null) {
      state = Maps.newHashMap();
    }
    this.state = state;
  }

  public String getEncryptedState() throws BlobCrypterException {
    return this.crypter.wrap(this.state);
  }

  public String getRealCallbackUrl() {
    return this.state.get(OAuth2CallbackState.REAL_CALLBACK_URL_KEY);
  }

  public void setRealCallbackUrl(final String realCallbackUrl) {
    this.state.put(OAuth2CallbackState.REAL_CALLBACK_URL_KEY, realCallbackUrl);
  }
}
