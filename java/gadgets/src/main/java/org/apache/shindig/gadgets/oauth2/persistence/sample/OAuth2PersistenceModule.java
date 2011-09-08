/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */
package org.apache.shindig.gadgets.oauth2.persistence.sample;

import org.apache.shindig.gadgets.oauth2.persistence.OAuth2Cache;
import org.apache.shindig.gadgets.oauth2.persistence.OAuth2Encrypter;
import org.apache.shindig.gadgets.oauth2.persistence.OAuth2Persister;

import com.google.inject.AbstractModule;

//NO IBM CONFIDENTIAL CODE OR INFORMATION!

public class OAuth2PersistenceModule extends AbstractModule {
  @Override
  protected void configure() {
    this.bind(OAuth2Persister.class).to(OAuth2PersisterImpl.class);
    this.bind(OAuth2Cache.class).to(OAuth2CacheImpl.class);
    this.bind(OAuth2Encrypter.class).to(OAuth2EncrypterImpl.class);
  }
}