# Confluence plugin for http header authentication (SSO / Kerberos)

This plugin provides authentication based on a http header  (default: X_Forwarded_User). 
The authenticator will fall back to the default Confluence authenticator, so everything external should keep working as expected. 

WARNING: This plugin is currently not actively developed or maintained. 
It was created for an organisation that no longer does or uses FOSS, so it was moved. 
Feel free to use it at your own risk, or to fork and improve it. 
I hope it is helpful anyway.

## License 

This software is distributed under the MIT License. See COPYING for details. 

## Install
There are a few things you need in order to install this plugin:

* Get the Atlassian SDK as described at [Atlassian](https://developer.atlassian.com/display/DOCS/Set+up+the+Atlassian+Plugin+SDK+and+Build+a+Project)
* Build the .jar file with the `atlas-package` command in the root folder (containing the pom.xml) 
* Stop your Confluence instance if it is running
* Copy the target/russo-confluence-1.0.jar file to the WEB-INF/libs folder of your Confluence installation
* Modify the WEB-INF/classes/seraph-config.xml file by commenting out existing auth classes and adding `<authenticator class="ch.fuchsnet.confluence.RussoConfluenceAuthenticator"/>`
* Restart your Confluence instance
* If it doesn't work as expected, check your Confluence logs. If you need more verbose information, set useDebug to true and recompile and reinstall the package

## Configuring your httpd

In order to get it to work, you need to configure your httpd (e.g. Apache httpd) to do the authentication and set the header. 
For security reasons you should make sure that user-set headers are removed, otherwise users will be able to spoof authentication
and log in as a different user! 

Example Apache configuration

```
<VirtualHost *:443>
SSLEngine on
SSLCertificateFile /etc/pki/tls/certs/mypubliccert.pem
SSLCertificateKeyFile /etc/pki/tls/private/privatekey.pem
ProxyPreserveHost On
ProxyRequests Off
ServerName wiki.mycompany.tld
ProxyPass / http://localhost:8080/
ProxyPassReverse / http://localhost:8080/
SSLProxyEngine On

    <Location />
        AuthType Kerberos
        AuthName "Confluence Kerberos Auth"
        KrbMethodNegotiate On
        KrbMethodK5Passwd On
        KrbAuthRealms MYREALM
        Krb5KeyTab /etc/httpd/httpd.keytab
        KrbLocalUserMapping On
        require valid-user
        RequestHeader set X-Forwarded-User %{REMOTE_USER}s
    </Location>
</VirtualHost>

```
