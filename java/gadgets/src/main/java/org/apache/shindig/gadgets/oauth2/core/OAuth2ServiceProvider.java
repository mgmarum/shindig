/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */
package org.apache.shindig.gadgets.oauth2.core;

import java.io.Serializable;



//  NO IBM CONFIDENTIAL CODE OR INFORMATION!
public class OAuth2ServiceProvider implements Serializable {

    private static final long serialVersionUID = 3476228373679048L;

    public final String authorizationURL;
    public final String accessTokenURL;

    public OAuth2ServiceProvider(String authorizationURL, String accessTokenURL) {
        this.authorizationURL = authorizationURL;
        this.accessTokenURL = accessTokenURL;
    }

    public int hashCode() {
    	final int prime = 31;
    	int result = 1;
    	result = prime * result
			+ ((accessTokenURL == null) ? 0 : accessTokenURL.hashCode());
	    result = prime * result
		    + ((authorizationURL == null) ? 0 : authorizationURL.hashCode());
	    return result;
    }

    public boolean equals(Object obj) {
    	if (this == obj)
    		return true;
    	if (obj == null)
    		return false;
    	if (getClass() != obj.getClass())
    		return false;
    	OAuth2ServiceProvider other = (OAuth2ServiceProvider) obj;
    	if (accessTokenURL == null) {
    		if (other.accessTokenURL != null)
    			return false;
    	} else if (!accessTokenURL.equals(other.accessTokenURL))
    		return false;
    	if (authorizationURL == null) {
    		if (other.authorizationURL != null)
    			return false;
    	} else if (!authorizationURL.equals(other.authorizationURL))
    		return false;
    	return true;
    }

}
