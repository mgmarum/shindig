/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */

package org.apache.shindig.gadgets.oauth2.sample;

import java.io.File;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.shindig.common.Nullable;
import org.apache.shindig.common.crypto.BasicBlobCrypter;
import org.apache.shindig.common.crypto.BlobCrypter;
import org.apache.shindig.common.crypto.Crypto;
import org.apache.shindig.common.logging.i18n.MessageKeys;
import org.apache.shindig.common.servlet.Authority;
import org.apache.shindig.common.util.ResourceLoader;
import org.apache.shindig.gadgets.GadgetException;
import org.apache.shindig.gadgets.http.HttpFetcher;
import org.apache.shindig.gadgets.oauth2.OAuth2Client;
import org.apache.shindig.gadgets.oauth2.OAuth2FetcherConfig;
import org.apache.shindig.gadgets.oauth2.OAuth2Request;
import org.apache.shindig.gadgets.oauth2.OAuth2Store;
import org.apache.shindig.gadgets.oauth2.persistence.OAuth2Cache;
import org.apache.shindig.gadgets.oauth2.persistence.OAuth2Encrypter;
import org.apache.shindig.gadgets.oauth2.persistence.OAuth2Persister;
import org.apache.shindig.gadgets.oauth2.persistence.sample.OAuth2PersisterImpl;

import com.google.inject.AbstractModule;
import com.google.inject.Inject;
import com.google.inject.Provider;
import com.google.inject.Singleton;
import com.google.inject.name.Named;

// NO IBM CONFIDENTIAL CODE OR INFORMATION!

public class OAuth2Module extends AbstractModule {
  private static final String LOG_CLASS = OAuth2Module.class.getName();
  private static final Level LOG_LEVEL = Level.FINER;
  private static final Logger LOGGER = Logger.getLogger(OAuth2Module.LOG_CLASS);

  private static final String OAUTH2_SIGNING_KEY_FILE = "shindig.signing.oauth2.key-file";
  private static final String OAUTH2_SIGNING_KEY_NAME = "shindig.signing.oauth2.key-name";
  private static final String OAUTH2_REDIRECT_URI = "shindig.signing.oauth2.global-redirect-uri";
  private static final String OAUTH2_IMPORT = "shindig.oauth2.import";
  private static final String OAUTH2_IMPORT_CLEAN = "shindig.oauth2.import.clean";

  @Override
  protected void configure() {
    // Used for persistent storage of OAuth2 access tokens.
    this.bind(OAuth2Store.class).toProvider(OAuth2StoreProvider.class);
    this.bind(OAuth2Request.class).toProvider(OAuth2RequestProvider.class);
  }

  @Singleton
  public static class OAuth2CrypterProvider implements Provider<BlobCrypter> {

    private final BlobCrypter crypter;

    @Inject
    public OAuth2CrypterProvider(@Named("shindig.signing.state-key") final String stateCrypterPath)
        throws IOException {
      if (StringUtils.isBlank(stateCrypterPath)) {
        OAuth2Module.LOGGER.info("Using random key for OAuth client-side state encryption");
        if (OAuth2Module.LOGGER.isLoggable(Level.INFO)) {
          OAuth2Module.LOGGER.logp(Level.INFO, OAuth2Module.LOG_CLASS,
              "OAuthCrypterProvider constructor", MessageKeys.USING_RANDOM_KEY);
        }
        this.crypter = new BasicBlobCrypter(
            Crypto.getRandomBytes(BasicBlobCrypter.MASTER_KEY_MIN_LEN));
      } else {
        if (OAuth2Module.LOGGER.isLoggable(Level.INFO)) {
          OAuth2Module.LOGGER.logp(Level.INFO, OAuth2Module.LOG_CLASS,
              "OAuthCrypterProvider constructor", MessageKeys.USING_FILE,
              new Object[] { stateCrypterPath });
        }
        this.crypter = new BasicBlobCrypter(new File(stateCrypterPath));
      }
    }

    public BlobCrypter get() {
      return this.crypter;
    }
  }

  public static class OAuth2RequestProvider implements Provider<OAuth2Request> {
    private final HttpFetcher fetcher;
    private final OAuth2FetcherConfig config;

    @Inject
    public OAuth2RequestProvider(final HttpFetcher fetcher, final OAuth2FetcherConfig config) {
      this.fetcher = fetcher;
      this.config = config;
    }

    public OAuth2Request get() {
      return new BasicOAuth2Request(this.config, this.fetcher);
    }
  }

  @Singleton
  public static class OAuth2StoreProvider implements Provider<OAuth2Store> {

    private final OAuth2Store store;

    @Inject
    public OAuth2StoreProvider(
        @Named(OAuth2Module.OAUTH2_SIGNING_KEY_FILE) final String signingKeyFile,
        @Named(OAuth2Module.OAUTH2_SIGNING_KEY_NAME) final String signingKeyName,
        @Named(OAuth2Module.OAUTH2_REDIRECT_URI) final String defaultRedirectUri,
        @Named(OAuth2Module.OAUTH2_IMPORT) final boolean importFromConfig,
        @Named(OAuth2Module.OAUTH2_IMPORT_CLEAN) final boolean importClean,
        final Provider<Authority> hostProvider, final OAuth2Cache cache,
        final OAuth2Persister persister, final OAuth2Encrypter encrypter,
        final String globalRedirectUri,
        @Nullable @Named("shindig.contextroot") final String contextRoot) {
      this.store = new BasicOAuth2Store(cache, persister);

      this.store.setDefaultRedirectUri(defaultRedirectUri);
      this.store.setHostProvider(hostProvider);
      
      if (importFromConfig) {
        final OAuth2Persister source = new OAuth2PersisterImpl(encrypter, hostProvider,
            globalRedirectUri, contextRoot);
        this.store.runImport(source, persister, importClean);
      }

      try {
        this.store.init();
      } catch (final GadgetException e) {
        e.printStackTrace();
      }
      
      this.loadDefaultKey(signingKeyFile, signingKeyName);
    }

    private void loadDefaultKey(final String signingKeyFile, final String signingKeyName) {
      final OAuth2Client client = null;
      if (!StringUtils.isBlank(signingKeyFile)) {
        try {
          if (OAuth2Module.LOGGER.isLoggable(Level.INFO)) {
            OAuth2Module.LOGGER.logp(Level.INFO, OAuth2Module.LOG_CLASS, "loadDefaultKey",
                MessageKeys.LOAD_KEY_FILE_FROM, new Object[] { signingKeyFile });
          }
          IOUtils.toString(ResourceLoader.open(signingKeyFile), "UTF-8");
        } catch (final Throwable t) {
          if (OAuth2Module.LOGGER.isLoggable(Level.WARNING)) {
            OAuth2Module.LOGGER.logp(Level.WARNING, OAuth2Module.LOG_CLASS, "loadDefaultKey",
                MessageKeys.COULD_NOT_LOAD_KEY_FILE, new Object[] { signingKeyFile });
            OAuth2Module.LOGGER
                .logp(Level.WARNING, OAuth2Module.LOG_CLASS, "loadDefaultKey", "", t);
          }
        }
      }
      if (client != null) {
        this.store.setDefaultClient(client);
      } else {
        if (OAuth2Module.LOGGER.isLoggable(Level.WARNING)) {
          OAuth2Module.LOGGER.logp(Level.WARNING, OAuth2Module.LOG_CLASS, "loadDefaultKey",
              MessageKeys.COULD_NOT_LOAD_SIGN_KEY, new Object[] {
                  OAuth2Module.OAUTH2_SIGNING_KEY_FILE, OAuth2Module.OAUTH2_SIGNING_KEY_NAME });
        }
      }
    }

    public OAuth2Store get() {
      return this.store;
    }
  }
}
