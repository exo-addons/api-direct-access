# Introduction

This addon allow to directly access to eXo API, without using the standard configured authentication. 

It can be used in context with SAML, OIDC, or other SSO to make API call, without having to authenticate in the SSO system.


# How to install
Launch this commands :
```
cd ${EXO_HOME}
./addon install exo-api-direct-access
```

# How to configure
Create a service user which will make API call. In function of your needs, this user must have users or administrators rights

# How to use
In the first version, this addon allow BASIC authentication. Add a header named `Authorization` in your request, following [documentation](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Authorization) :

For "Basic" authentication the credentials are constructed by first combining the username and the password with a colon (john:password), and then by encoding the resulting string in base64 (am9objpwYXNzd29yZA==).

`Authorization: Basic am9objpwYXNzd29yZA==`

> [!WARNING]  
> Base64-encoding can easily be reversed to obtain the original name and password, so Basic authentication is completely insecure. HTTPS is always recommended when using authentication, but is even more so when using Basic authentication.`



