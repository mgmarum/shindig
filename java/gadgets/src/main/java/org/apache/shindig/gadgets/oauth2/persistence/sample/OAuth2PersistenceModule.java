package org.apache.shindig.gadgets.oauth2.persistence.sample;

import org.apache.shindig.gadgets.oauth2.persistence.OAuth2Cache;
import org.apache.shindig.gadgets.oauth2.persistence.OAuth2Encrypter;
import org.apache.shindig.gadgets.oauth2.persistence.OAuth2Persistence;

import com.google.inject.AbstractModule;

public class OAuth2PersistenceModule extends AbstractModule {
  @Override
  protected void configure() {
    this.bind(OAuth2Persistence.class).to(OAuth2PersistenceImpl.class);
    this.bind(OAuth2Cache.class).to(OAuth2CacheImpl.class);
    this.bind(OAuth2Encrypter.class).to(OAuth2EncrypterImpl.class);
  }
}