// It is using this package as I needed to call a protected package in BasicAuthenticator 
package org.apache.catalina.authenticator;

import java.io.IOException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
 
import javax.servlet.ServletException;
 
import org.apache.catalina.Context;
import org.apache.catalina.Pipeline;
import org.apache.catalina.Realm;
import org.apache.catalina.Session;
import org.apache.catalina.Valve;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;

/*
 * Allows auto login in tomcat so we can bypass the BASIC authentication,
 * which causes us so many problems with functional tests
 * 
 * Based on the code at http://code.google.com/p/jugile-web2/source/browse/trunk/src/org/jugile/tomcat/AutoLoginValve.java?r=2
 * 
 * Entry in server.xml will look something like  
 * <Valve className="org.apache.catalina.authenticator.BasicAutoLoginValve" 
 *   	  trustedAddresses="127.0.0.1"
 *   	  userId="xyz"
 *   	  password="abc"
 *   	  loggingEnabled="false"/>
 * trustedAddresses and roles can be a semi-colon list of values
 * trustedAddresses only needs to be the start of the address, so if you want all addresses that begin with 192.168.1 to be trusted then you only need to set trustedAddresses to "192.168.1"
 * 
 * In addition the following request parameters can be specified
 * 		__autologin__ set to no if you do not want auto login to kick in (yes/*no)
 *  	__userid__ the user you want to login as, overrides the default from server.xml
 *  	__password__ the password to be used for the user, overrides the default from server.xml
 *  
 * Auto login will not occur in any of the following circumstances
 * 		1. the clients ip address is not prefixed by one of the trustedAddresses in server.xml
 * 		2. the request parameter __autologin__ is set to "no"
 * 		3. the userId in server.xml is not set and the request parameter __userid__ is not set
 * 		4. the password in server.xml is not set and the request parameter __password__ is not set
 */
public class BasicAutoLoginValve extends ValveBase {
	static private final String PARAMETER_AUTOLOGIN = "__autologin__";
	static private final String PARAMETER_PASSWORD = "__password__";
	static private final String PARAMETER_USERID = "__userid__";
	static private final String YES = "yes";
    private List<String> trustedAddresses = new ArrayList<String>();
    private String userId;
    private String password;
    private Boolean loggingEnabled = new Boolean(false);
    
    // To ensure the SSO stuff kicks in with the basicAuthenticator
    private boolean started = false;
    private BasicAuthenticator basicAuthenticator = null;
    
    public BasicAutoLoginValve() {
    }
 
    public synchronized void start(Context context) {
    	if (!started) {
    		// Locate the basic authenticator valve, so we can register the principal with it
    		// Must have at least one valve, otherwise we wouldn't be in here ...
    		Valve[] valves = ((Pipeline)context).getValves();
    		for (int i = 0; i < valves.length; ++i) {
    			if (valves[i] instanceof BasicAuthenticator) {
    				basicAuthenticator = ((BasicAuthenticator)valves[i]);
    				break;
    			}
    		}
	    	this.started = true;
    	}
    }

    @Override
    public void invoke(final Request request, final Response response) 
             throws IOException, ServletException {
    	// If we already logged in for the session then we do not need to auto login
    	if (request.getUserPrincipal() == null) {
    		if (!started) {
    			// There must be a better way to initialise this than to check whether we have started each time
    			// Unfortunately postRegister is called to soon as the contexts we are interested in havn't been loaded at that point
    			start(request.getContext());
    		}
    		
	        final String remoteAddr = request.getRemoteAddr();
	        final String forwarded = request.getHeader("X-Forwarded-For");
	        final boolean isTrustedIp = isTrusted(request, remoteAddr) || isTrusted(request, forwarded);
	        if (loggingEnabled) {
		        dumpHeaders(request);
		        containerLog.debug("remoteAddr: " + remoteAddr);
		        containerLog.debug("forwarded-for: " + forwarded);
		        containerLog.debug("trusted ip: " + trustedAddresses.toString());
		        containerLog.debug("isTrustedIp: " + isTrustedIp);
	        }
	        
	        if (isTrustedIp) {
	        	// Do we already have one stored in the session
	            Principal principal = null;
	        	Session session = request.getSessionInternal();
	        	if (session != null) {
	        		// See whether we are already logged in or not
	        		principal = (Principal)session.getPrincipal();
	        	}
	        	
	            if (principal == null) {
	            	// We haven't previously logged in, so see if we need to auto login
		        	String username = getParametrValue(request, PARAMETER_USERID, userId);
		            final String credentials = getParametrValue(request, PARAMETER_PASSWORD, password);;
		            if (((username != null) && !username.isEmpty()) &&
		            	((credentials != null) && !credentials.isEmpty())) {
			            Realm r = request.getContext().getRealm();
			            principal = r.authenticate(username, credentials);
			            if ((basicAuthenticator != null) &&
			            	(principal != null)) {
			            	basicAuthenticator.register(request, response, principal, "BASIC", username, credentials);
			            }
		            }
	            }
	        }
    	}
        getNext().invoke(request, response);
    }

    private String getParametrValue(final Request request, String parameterName, String defaultValue) {
    	String value = request.getParameter(parameterName);
    	
    	if ((value == null) || value.isEmpty()) {
    		value = defaultValue;
    	}
    	return(value);
    }
    
    private boolean isTrusted(final Request request, String ipAddress) {
    	boolean trusted = false;
    	
        if (ipAddress != null) {
        	for (String trustedAddress : trustedAddresses) {
                if (ipAddress.startsWith(trustedAddress)) {
                	String autoLogin = getParametrValue(request, PARAMETER_AUTOLOGIN, YES);
                	if (autoLogin.equals(YES)) {
                		trusted = true;
                	}
                	break;
                }
        	}
        }
        return(trusted);
    }
 
    private void convertToList(final String string, List<String> list, String name) {
    	if ((string != null) && !string.isEmpty()) {
    		String [] stringArray = string.split(";");
    		for (String stringElement : stringArray) {
    			String trimmed = stringElement.trim();
    			if (!trimmed.isEmpty()) {
    				list.add(trimmed);
    			}
    		}
    	}
    	if (name != null) {
    		containerLog.debug(name + ": " + list.toString());
    	}
    }
 
    public void setTrustedAddresses(final String trustedAddresses) {
    	convertToList(trustedAddresses, this.trustedAddresses, "setTrusedAddresses");
    }
 
    public void setUserId(final String userId) {
    	if ((userId != null) && !userId.isEmpty()) {
    		containerLog.debug("setUserId: " + userId);
	        this.userId = userId;
    	}
    }
 
    public void setPassword(final String password) {
    	if ((password != null) && !password.isEmpty()) {
    		containerLog.debug("setPassword: " + password);
    		this.password = password;
    	}
    }
    
    public void setLoggingEnabled(final Boolean loggingEnabled) {
    	if (loggingEnabled != null) {
    		containerLog.debug("setLoggingEnabled: " + loggingEnabled);
    		this.loggingEnabled = loggingEnabled;
    	}
    }

    private void dumpHeaders(Request r) {
    	containerLog.debug("All headers:");

        @SuppressWarnings("rawtypes")
		Enumeration en = r.getHeaderNames();
 
        while (en.hasMoreElements()) {
            String name = (String)en.nextElement();
            String value = r.getHeader(name);
            containerLog.debug(name + " = \"" + value + "\"");
        }
    }
}
