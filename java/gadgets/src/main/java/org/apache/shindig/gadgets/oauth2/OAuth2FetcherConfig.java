/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */
package org.apache.shindig.gadgets.oauth2;

import org.apache.shindig.common.crypto.BlobCrypter;
import org.apache.shindig.common.util.TimeSource;

import com.google.inject.Inject;
import com.google.inject.name.Named;

// NO IBM CONFIDENTIAL CODE OR INFORMATION!

/**
 * Configuration parameters for an OAuth2Request
 */
public class OAuth2FetcherConfig {

  public static final String OAUTH_STATE_CRYPTER = "shindig.oauth.state-crypter";

  private final BlobCrypter stateCrypter;
  private final GadgetOAuth2TokenStore tokenStore;
  private final TimeSource clock;
  private final boolean viewerAccessTokensEnabled;

  @Inject
  public OAuth2FetcherConfig(
      @Named(OAuth2FetcherConfig.OAUTH_STATE_CRYPTER) final BlobCrypter stateCrypter,
      final GadgetOAuth2TokenStore tokenStore, final TimeSource clock,
      @Named("shindig.signing.viewer-access-tokens-enabled") final boolean viewerAccessTokensEnabled) {
    this.stateCrypter = stateCrypter;
    this.tokenStore = tokenStore;
    this.clock = clock;
    this.viewerAccessTokensEnabled = viewerAccessTokensEnabled;
  }

  /**
   * @return A BlobCrypter Used to encrypt state stored on the client.
   */
  public BlobCrypter getStateCrypter() {
    return this.stateCrypter;
  }

  /**
   * @return the persistent token storage.
   */
  public GadgetOAuth2TokenStore getTokenStore() {
    return this.tokenStore;
  }

  /**
   * @return the Clock
   */
  public TimeSource getClock() {
    return this.clock;
  }

  /**
   * @return true if the owner pages do not allow user controlled javascript
   */
  public boolean isViewerAccessTokensEnabled() {
    return this.viewerAccessTokensEnabled;
  }
}
