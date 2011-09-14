package org.apache.shindig.gadgets.oauth2;

import java.io.Serializable;


public interface OAuth2Token extends Serializable {
  public enum Type {
    ACCESS, REFRESH
  }

  public int getExpiresIn();

  public String getGadgetUri();

  public String getProviderName();

  public String getScope();

  public String getSecret();

  public String getTokenType();

  public Type getType();

  public String getUser();

  public void setExpiresIn(int expiresIn);

  public void setGadgetUri(String gadgetUri);

  public void setProviderName(String providerName);

  public void setScope(String scope);

  public void setSecret(String secret) throws OAuth2EncryptionException;

  public void setTokenType(String tokenType);

  public void setType(Type type);

  public void setUser(String user);
}
