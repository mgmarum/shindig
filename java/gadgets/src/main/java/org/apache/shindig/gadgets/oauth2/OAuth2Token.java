package org.apache.shindig.gadgets.oauth2;

import java.io.Serializable;

public interface OAuth2Token extends Serializable {
  public enum Type {
    ACCESS, REFRESH
  }

  public Type getType();

  public void setType(Type type);

  public String getToken();

  public void setToken(String token);

  public String getSecret();

  public void setSecret(String secret);

  public String getEncryptedSecret();

  public void setEncryptedSecret(String encryptedSecret);

  public String getProviderName();

  public void setProviderName(String providerName);

  public String getGadgetUri();

  public void setGadgetUri(String gadgetUri);

  public String getUser();

  public void setUser(String user);

  public String getScope();

  public void setScope(String scope);
}
