/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */
package org.apache.shindig.gadgets.oauth2.core;

import java.util.Map;

// NO IBM CONFIDENTIAL CODE OR INFORMATION!

public interface Parameter extends Map.Entry<String, String> {
  public String getKey();

  public String getValue();

  public String setValue(String value);

}
