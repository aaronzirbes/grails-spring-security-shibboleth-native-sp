Shibboleth Naitive SP support Spring Security Core
==================================================

User Documentation
==================

The official docs are [here](http://aaronzirbes.github.com/grails-spring-security-shibboleth-native-sp/).

General Information
===================

The Shibboleth Native SP adds support for attributes exposed by a Native Shibboleth SP through Apache on up to the Java servlet container. This plugin doesn't implement the Shibboleth SP inside the java container, but uses the recommeneded Native SP provided as a server daemon and an apache module. The ensures that security vulnarabilities specific to the SP are updated in a timely fashion. This plugin let's the shibd daemon, Apache, and Tomcat do most of the heavy lifting. By the time the http request gets to the application, the only thing this plug-in does is look for the exposed attributes expected from a Shibboleth Native SP implementation and validate that they are what was expected.

Because of the nature of the Shibboleth Native SP, this plugin will only work when deployed to a shibboleth-aware servlet container. The side effect of this is that authentication via shibboleth is not available when running through the grails command line. You can only effectively use this plugin when it is deployed as a WAR to your production or staging server. To help you run your application in development mode, the spring-security-mock plugin is recommended.

Jenkins/Hudson Integration
==========================

[This](https://github.com/aaronzirbes/grails-spring-security-shibboleth-native-sp) github repository auto-build via Jenkins CI, so you can set up your own Jenkins CI build by using the following build command:

	clean compile doc package-plugin "test-app -coverage -xml" codenarc

If you are using Jenkins, you should have the following Jenkins plugins installed:

 * grails
 * git
 * cobertura
 * violations
 * javadoc

Building from the command line
==============================

You can build this plugin from the command line by running

	grails package-plugin

You can generate the user manual and JavaDocs by running

	grails doc

You can run the test suite by running

	grails test-app -coverage

