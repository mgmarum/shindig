/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */
package org.apache.shindig.gadgets.oauth2;

import org.apache.shindig.common.util.TimeSource;

import com.google.inject.Inject;
import com.google.inject.name.Named;

// NO IBM CONFIDENTIAL CODE OR INFORMATION!

public class OAuth2FetcherConfig {
  private final GadgetOAuth2TokenStore tokenStore;
  private final TimeSource clock;

  @Inject
  public OAuth2FetcherConfig(final GadgetOAuth2TokenStore tokenStore, final TimeSource clock,
      @Named("shindig.signing.viewer-access-tokens-enabled") final boolean viewerAccessTokensEnabled) {
    this.tokenStore = tokenStore;
    this.clock = clock;
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
}
