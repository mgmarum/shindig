/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */

package org.apache.shindig.gadgets.oauth2.sample;

import org.apache.shindig.gadgets.oauth2.OAuth2Message;

import com.google.inject.AbstractModule;
import com.google.inject.Inject;
import com.google.inject.Provider;

// NO IBM CONFIDENTIAL CODE OR INFORMATION!

public class OAuth2MessageModule extends AbstractModule {

  @Override
  protected void configure() {
    this.bind(OAuth2Message.class).toProvider(OAuth2MessageProvider.class);
  }

  public static class OAuth2MessageProvider implements Provider<OAuth2Message> {
    @Inject
    public OAuth2MessageProvider() {
    }

    public OAuth2Message get() {
      return new BasicOAuth2Message();
    }
  }
}