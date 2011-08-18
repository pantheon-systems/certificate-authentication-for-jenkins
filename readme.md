Building and installing
=======================

1. Install a JDK and Maven.
2. Run "mvn package"
3. Configure Tomcat to request or require clientAuth in the Connector.
4. Install the target/certificate-auth-plugin.hpi as a Jenkins plugin.
5. Restart Jenkins (probably via a restart of Tomcat).
6. Under system configuration, select "Certificate" as the source of user identity.
7. Try requesting a page with a client certificate.
