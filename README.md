# Introduction

> [!WARNING]  
> This addon is only for eXo Platform 6.5.x ! In 6.6.x and above, this code is present in the product.
> 20250131 : the work to introduce this addon in product code was not done today. As we need this addon in a customer context, we release a version for 7.0.x
> We still plan to have this addon in product code for 7.0.0-GA

This addon allows to extends default eXo SAML behaviour. In some context, the user identifier is not in the subject which contains named-id with a persistent format, or with a transient format.
In such case, the user identifier is present in assertion attributes.


# How to install
Launch this commands :
```bash
cd ${EXO_HOME}
./addon install exo-saml-extensions
```

> [!WARNING]  
> This addon requires exo-saml addon. It must be installed after exo-saml addon.

# How to configure
Add these properties in exo.properties
```properties
gatein.sso.saml.use.namedid=false
gatein.sso.saml.subject.attribute=uid
```
| Property | Description                                                                            | Default Value |
|----|----------------------------------------------------------------------------------------|---------------|
| gatein.sso.saml.use.namedid | To define if eXo must use nameid to identify the user                                  | true          |
| gatein.sso.saml.subject.attribute | If previous property is set to false, which attribute must be used to identity the user | uid           |

