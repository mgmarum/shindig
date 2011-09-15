/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */
package org.apache.shindig.gadgets.oauth2;

import com.google.inject.Inject;

// NO IBM CONFIDENTIAL CODE OR INFORMATION!

public class OAuth2FetcherConfig {
  private final GadgetOAuth2TokenStore tokenStore;

  @Inject
  public OAuth2FetcherConfig(final GadgetOAuth2TokenStore tokenStore) {
    this.tokenStore = tokenStore;
  }

  /**
   * @return the persistent token storage.
   */
  public GadgetOAuth2TokenStore getTokenStore() {
    return this.tokenStore;
  }

  public OAuth2Store getOAuth2Store() {
    return this.tokenStore.getOAuth2Store();
  }
}
