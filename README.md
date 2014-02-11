TomcatBasicAutoLoginValve
=========================

Enables Auto Logging in for Basic Authentication with Tomcat, to cater for Selenium not dealing with Basic Authentication

Originally based on the code found at http://code.google.com/p/jugile-web2/source/browse/trunk/src/org/jugile/tomcat/AutoLoginValve.java?r=2
unfortunately that did not completely suit our needs as we use SSO for many webapps in the same host and we wanted to test different users who have varying roles.

The jar file needs to reside in the tomcat/lib directory and not the lib directory of your webapp.

This tomcat valve allows you to auto login either by specifying a userid and password in the server.xml or by 
specifying the userid and password in predefined attributes.

For this valve to kick in you need to add the following to your server.xml,
either under the Context or Host elements for where you want it to take effect.
the jar file needs to live in your tomcat/lib directory

<Valve className="org.apache.catalina.authenticator.BasicAutoLoginValve" 
	   trustedAddresses="<semi colon list of trusted ip addresses>"
   	   userId="<userid>"
   	   password="<password for userid>"
	   loggingEnabled="<true or false>"/>
	   
The trustedAddresses only needs to be the start of the address if you want to allow all addresses in that range,
eg. If you trust all addresses that begin with 192.168.1 then you only need to set trustedAddresses to "192.168.1"

If the remote ipaddress does not begin with a trusted address then auto login will not kick in.
The userid and password do not need to be specified if you are going to specify them on the request line.
Note: The userid and password do need to be valid as it calls the authenticate method on the realm, so that the relevant roles are setup for that user.

There are request parameters that will override the workings of the auto login valve and they are
 
 	__autologin__ set this to "no" if you do not want auto login to kick in, defaults to "yes"
  	__userid__ the user you want to login as, overrides the userid specified in server.xml
  	__password__ the password to be used for the user, overrides the password specified in server.xml
 
 
Auto login will only occur in the following circumstances
 	1. the clients ip address is prefixed by one of the trustedAddresses in server.xml
	2. the request parameter __autologin__ has not been specified or is set to "yes"
	3. the userId has been set in server.xml or has been specified by the request parameter __userid__
	4. the password has been set in server.xml or has been specified by the request parameter __password__
	5. the userid and password are a valid combination for the realm that authentication is to occur against
