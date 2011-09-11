package org.apache.shindig.gadgets.oauth2;

import java.io.Serializable;

import org.apache.shindig.gadgets.oauth2.persistence.OAuth2EncryptionException;

public interface OAuth2Token extends Serializable {
  public enum Type {
    ACCESS, REFRESH
  }

  public Type getType();

  public void setType(Type type);

  public String getSecret();

  public void setSecret(String secret) throws OAuth2EncryptionException;

  public String getEncryptedSecret();

  public void setEncryptedSecret(String encryptedSecret) throws OAuth2EncryptionException;

  public String getProviderName();

  public void setProviderName(String providerName);

  public String getGadgetUri();

  public void setGadgetUri(String gadgetUri);

  public String getUser();

  public void setUser(String user);

  public String getScope();

  public void setScope(String scope);

  public int getExpiresIn();

  public void setExpiresIn(int expiresIn);

  public String getTokenType();

  public void setTokenType(String tokenType);
}
