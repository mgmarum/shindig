/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */
package org.apache.shindig.gadgets.oauth2.persistence.sample;

import java.io.IOException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import org.apache.shindig.common.Nullable;
import org.apache.shindig.common.servlet.Authority;
import org.apache.shindig.common.util.ResourceLoader;
import org.apache.shindig.gadgets.oauth2.OAuth2Client;
import org.apache.shindig.gadgets.oauth2.OAuth2EncryptionException;
import org.apache.shindig.gadgets.oauth2.OAuth2Message;
import org.apache.shindig.gadgets.oauth2.OAuth2Provider;
import org.apache.shindig.gadgets.oauth2.OAuth2Token;
import org.apache.shindig.gadgets.oauth2.OAuth2Token.Type;
import org.apache.shindig.gadgets.oauth2.persistence.OAuth2ClientPersistence;
import org.apache.shindig.gadgets.oauth2.persistence.OAuth2Encrypter;
import org.apache.shindig.gadgets.oauth2.persistence.OAuth2PersistenceException;
import org.apache.shindig.gadgets.oauth2.persistence.OAuth2Persister;
import org.apache.shindig.gadgets.oauth2.persistence.OAuth2ProviderPersistence;
import org.apache.shindig.gadgets.oauth2.persistence.OAuth2TokenPersistence;
import org.json.JSONException;
import org.json.JSONObject;

import com.google.inject.Inject;
import com.google.inject.Provider;
import com.google.inject.Singleton;
import com.google.inject.name.Named;

// NO IBM CONFIDENTIAL CODE OR INFORMATION!

@Singleton
public class OAuth2PersisterImpl implements OAuth2Persister {
  private static final String NO_CLIENT_AUTHENTICATION = "NONE";
  private static final String CLIENT_AUTHENTICATION = "client_authentication";
  private static final String CLIENTS = "clients";
  private static final String ENDPOINTS = "endpoints";
  private static final String TYPE = "type";
  private static final String AUTHORIZATION_URL = "authorizationUrl";
  private static final String TOKEN_URL = "tokenUrl";
  private static final String OAUTH2_CONFIG = "config/oauth2.json";

  private final OAuth2Encrypter encrypter;
  private final Provider<Authority> hostProvider;
  private final String globalRedirectUri;
  private final String contextRoot;

  @Inject
  public OAuth2PersisterImpl(final OAuth2Encrypter encrypter,
      final Provider<Authority> hostProvider, final String globalRedirectUri,
      @Nullable @Named("shindig.contextroot") final String contextRoot) {
    this.encrypter = encrypter;
    this.hostProvider = hostProvider;
    this.globalRedirectUri = globalRedirectUri;
    this.contextRoot = contextRoot;
  }

  private static String getJSONString(final String location) throws IOException {
    return ResourceLoader.getContent(location);
  }

  public Set<OAuth2Client> loadClients() throws OAuth2PersistenceException {
    final Set<OAuth2Client> ret = new HashSet<OAuth2Client>();

    try {
      final JSONObject providers = new JSONObject(
          OAuth2PersisterImpl.getJSONString(OAuth2PersisterImpl.OAUTH2_CONFIG));
      for (final Iterator<?> i = providers.keys(); i.hasNext();) {
        final String providerName = (String) i.next();
        final JSONObject provider = providers.getJSONObject(providerName);
        final JSONObject clients = provider.getJSONObject(OAuth2PersisterImpl.CLIENTS);
        for (final Iterator<?> j = clients.keys(); j.hasNext();) {
          String gadgetUri = (String) j.next();
          final JSONObject settings = clients.getJSONObject(gadgetUri);
          String redirectUri = settings.optString(OAuth2Message.REDIRECT_URI, null);
          if (redirectUri == null) {
            redirectUri = this.globalRedirectUri;
          }
          final String secret = settings.optString(OAuth2Message.CLIENT_SECRET);
          final String key = settings.getString(OAuth2Message.CLIENT_ID);
          final String typeS = settings.optString(OAuth2PersisterImpl.TYPE, null);
          String grantType = settings.optString(OAuth2Message.GRANT_TYPE, null);
          final OAuth2ClientPersistence client = new OAuth2ClientPersistence(this.encrypter);

          try {
            client.setEncryptedSecret(secret);
          } catch (final OAuth2EncryptionException e) {
            throw new OAuth2PersistenceException(e);
          }

          if (this.hostProvider != null) {
            gadgetUri = gadgetUri.replace("%authority%", this.hostProvider.get().getAuthority());
            gadgetUri = gadgetUri.replace("%contextRoot%", this.contextRoot);
            gadgetUri = gadgetUri.replace("%origin%", this.hostProvider.get().getOrigin());
          }
          client.setGadgetUri(gadgetUri);
          client.setKey(key);
          client.setProviderName(providerName);

          if (this.hostProvider != null) {
            redirectUri = redirectUri
                .replace("%authority%", this.hostProvider.get().getAuthority());
            redirectUri = redirectUri.replace("%contextRoot%", this.contextRoot);
            redirectUri = redirectUri.replace("%origin%", this.hostProvider.get().getOrigin());
            
          }
          client.setRedirectUri(redirectUri);

          if ((grantType == null) || (grantType.length() == 0)) {
            grantType = OAuth2Message.AUTHORIZATION;
          }

          client.setGrantType(grantType);

          OAuth2Client.Type type = OAuth2Client.Type.UNKNOWN;
          if (OAuth2Message.CONFIDENTIAL_CLIENT_TYPE.equals(typeS)) {
            type = OAuth2Client.Type.CONFIDENTIAL;
          } else if (OAuth2Message.PUBLIC_CLIENT_TYPE.equals(typeS)) {
            type = OAuth2Client.Type.PUBLIC;
          }
          client.setType(type);

          ret.add(client);
        }
      }
    } catch (final JSONException e) {
      e.printStackTrace();
      throw new OAuth2PersistenceException(e);
    } catch (final IOException e) {
      e.printStackTrace();
      throw new OAuth2PersistenceException(e);
    }

    return ret;
  }

  public Set<OAuth2Provider> loadProviders() throws OAuth2PersistenceException {
    final Set<OAuth2Provider> ret = new HashSet<OAuth2Provider>();

    try {
      final JSONObject providers = new JSONObject(
          OAuth2PersisterImpl.getJSONString(OAuth2PersisterImpl.OAUTH2_CONFIG));
      for (final Iterator<?> i = providers.keys(); i.hasNext();) {
        final String providerName = (String) i.next();
        final JSONObject provider = providers.getJSONObject(providerName);
        final JSONObject endpoints = provider.getJSONObject(OAuth2PersisterImpl.ENDPOINTS);

        final String clientAuthenticationType = provider
            .optString(OAuth2PersisterImpl.CLIENT_AUTHENTICATION,
                OAuth2PersisterImpl.NO_CLIENT_AUTHENTICATION);

        String authorizationUrl = endpoints.optString(OAuth2PersisterImpl.AUTHORIZATION_URL, null);

        if ((this.hostProvider != null) && (authorizationUrl != null)) {
          authorizationUrl = authorizationUrl.replace("%authority%", this.hostProvider.get()
              .getAuthority());
          authorizationUrl = authorizationUrl.replace("%contextRoot%", this.contextRoot);
          authorizationUrl = authorizationUrl.replace("%origin%", this.hostProvider.get().getOrigin());
          
        }

        String tokenUrl = endpoints.optString(OAuth2PersisterImpl.TOKEN_URL, null);
        if ((this.hostProvider != null) && (tokenUrl != null)) {
          tokenUrl = tokenUrl.replace("%authority%", this.hostProvider.get().getAuthority());
          tokenUrl = tokenUrl.replace("%contextRoot%", this.contextRoot);
          tokenUrl = tokenUrl.replace("%origin%", this.hostProvider.get().getOrigin());
        }

        final OAuth2Provider oauth2Provider = new OAuth2ProviderPersistence();

        oauth2Provider.setName(providerName);
        oauth2Provider.setAuthorizationUrl(authorizationUrl);
        oauth2Provider.setTokenUrl(tokenUrl);
        oauth2Provider.setClientAuthenticationType(clientAuthenticationType);

        ret.add(oauth2Provider);
      }
    } catch (final JSONException e) {
      e.printStackTrace();
      throw new OAuth2PersistenceException(e);
    } catch (final IOException e) {
      e.printStackTrace();
      throw new OAuth2PersistenceException(e);
    }

    return ret;
  }

  public Set<OAuth2Token> loadTokens() throws OAuth2PersistenceException {
    return Collections.emptySet();
  }

  public OAuth2Provider findProvider(final String providerName) throws OAuth2PersistenceException {
    return null;
  }

  public OAuth2Client findClient(final String providerName, final String gadgetUri)
      throws OAuth2PersistenceException {
    return null;
  }

  public OAuth2Token findToken(final String providerName, final String gadgetUri,
      final String user, final String scope, final Type type) throws OAuth2PersistenceException {
    return null;
  }

  public boolean removeToken(final String providerName, final String gadgetUri, final String user,
      final String scope, final Type type) {
    return false;
  }

  public OAuth2Token findToken(final Integer index) throws OAuth2PersistenceException {
    return null;
  }

  public boolean removeToken(final Integer index) throws OAuth2PersistenceException {
    return false;
  }

  public void insertToken(final OAuth2Token token) throws OAuth2PersistenceException {
  }

  public void updateToken(final OAuth2Token token) throws OAuth2PersistenceException {
  }

  public OAuth2Token createToken() {
    return new OAuth2TokenPersistence(this.encrypter);
  }

  public OAuth2Provider findProvider(final Integer index) throws OAuth2PersistenceException {
    return null;
  }

  public OAuth2Client findClient(final Integer index) throws OAuth2PersistenceException {
    return null;
  }
}
