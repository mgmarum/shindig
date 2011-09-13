/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */
package org.apache.shindig.gadgets.oauth2.persistence;

import org.apache.shindig.gadgets.oauth2.OAuth2EncryptionException;

// NO IBM CONFIDENTIAL CODE OR INFORMATION!

public interface OAuth2Encrypter {
  public String encrypt(String plainSecret) throws OAuth2EncryptionException;

  public String decrypt(String encryptedSecret) throws OAuth2EncryptionException;
}
