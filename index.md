--
title: "OAuth"
addon: "OAuth"
repo: "https://github.com/seedstack/oauth-addon"
author: Jyoti ATHALYE 
description: "Provides the ability to authenticate and authorize subjects using OAuth and OpenID Connect."
tags:
    - security
zones:
    - Addons
noMenu: true    
---

Seedstack OAuth add-on provides the ability to authenticate and authorize subjects using OAuth and OpenID Connect.

## Dependencies

{{< dependency g="org.seedstack.addons.oauth" a="oauth" v="1.0.0-SNAPSHOT">}}


### OAuth add-on supports 2 types of grants :
1. Authorisation Code Grant. 	
2. Client Credentials Grant.

Authorisation Code Grant flow is used when web application is the client to access any service using oauth.

Client Credentials Grant flow is used when end user interaction is not required to access any service using oauth.


### OAuth Pre-requisite

There are certain pre-requisites to be followed before starting to implement the oauth-addon in the project:

1. Decide the open-id/oauth provider and service to be accessed from the provider.
2. Register an application with provider and obtain its client id and client secret.

e.g with google as the open-id provider, 
    login to the google's developer api console and register the application to fetch client id and client secret.
	

## Configuration 

To implement the oauth add-on, its realm, oauth provider details, filter mapping urls must be specified in security configuration:

{{% config p="oauth" %}}
```yaml

providerBaseUrl: http://localhost:${sys.tomcat\.http\.port:'9090'}${web.runtime.servlet.contextPath}

rest:
  path: /api
  
security:
  # Name of realm, responsible for authenticating and authorizing subjects. 
  # Realm fetches user information from the authentication token.
  realms: OAuthRealm
  web:
	#In built filters are invoked based on the provided url mapping.
    urls:
      -
        pattern: /api/provider/**
        filters: anon
      -
	    # Based on the callback url sent by the provider, callback process is invoked.
		# This callback url pattern must match with redirect url set during app registration process.
        pattern: /callback
        filters: oauthCallback
      -
		# Based on the url pattern, oauth process is invoked.
        pattern: /profile.html
        filters: oauth
      - 
	    # Based on the url pattern, oauth process is invoked.
        pattern: /api/**
        filters: oauth
  oauth:
    # This url defines how clients dynamically discover information about OpenID Provider.
    discoveryDocument: (Absolute url in String format)
	
    # Redirection URI to which the authorisation response will be sent.
	redirect: (Absolute url in String format)
	
	# List of available resources, when they are used to access OAuth 2 protected endpoints.
    scopes: (List of comma separated values in String format)
	
	# Provides information about the service being accessed.
    clientId: (value in String format)
	
	# Means of authorising client.
    clientSecret: (value in String format)
	
	# Name of class which will provide custom validations for token if any.
	accessTokenValidator: (Fully qualified java class name which implements AccessTokenValidator interface)

	# In case, of the discovery url not provided by the provider, then manual provider configurations can be done 
	provider:
      authorization: ${providerBaseUrl}/api/provider/authorize
      token: ${providerBaseUrl}/api/provider/create-token
      revocation: ${providerBaseUrl}/api/provider/token/revoke
    openIdConnect:
      issuer: https://mockedserver.com
      jwks: ${providerBaseUrl}/JWKset.json
      userInfo: ${providerBaseUrl}/api/provider/userInfo
      unsecuredTokenAllowed: false
```	
	
### Example

Assuming, we are using google as the open-id provider, the following configuration needs to be done.

```yaml
security: 
  realms: OAuthRealm
  web:
    urls:
      -
        pattern: /api/provider/**
        filters: anon
      -
        pattern: /callback
        filters: oauthCallback
      -
        pattern: /profile.html
        filters: oauth
      - 
        pattern: /api/**
        filters: oauth
  oauth:
    discoveryDocument: https://accounts.google.com/.well-known/openid-configuration
	redirect: http://localhost:8080/callback
    scopes: email
    clientId: 243402117109-3ia596dogjjo.client.id
    clientSecret: 2f_1qSp1Nhah9.tclientSecret

```	

### Example Usage to invoke Client Credentials Grant and fetch the AccessToken

public class SomeClass{

	@Inject
    private OAuthService oauthService;
	
	private void getAuthenticationToken(){
		oauthService.getTokenFromClientCredentials();
	}	

}
