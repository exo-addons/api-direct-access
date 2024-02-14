/*
 * Copyright (C) 2024 eXo Platform SAS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
package org.exoplatform.addons.apidirectaccess;

import javax.servlet.http.HttpServletRequest;
import org.exoplatform.services.log.ExoLogger;
import org.exoplatform.services.log.Log;
import org.exoplatform.services.security.Authenticator;
import org.exoplatform.services.security.Credential;
import org.exoplatform.services.security.PasswordCredential;
import org.exoplatform.services.security.UsernameCredential;
import org.exoplatform.services.security.j2ee.TomcatLoginModule;
import org.gatein.sso.agent.tomcat.ServletAccess;

import javax.security.auth.login.LoginException;
import java.util.Base64;

public class BasicAuthRestLoginModule extends TomcatLoginModule {
  private static final Log LOG = ExoLogger.getLogger(BasicAuthRestLoginModule.class);

  @Override
  public boolean login() throws LoginException {
    try {
      //todo :
      // - add a property to explicitly activate BasicAuth
      // - Change to a more robust solution (API token in settings for example)

      HttpServletRequest servletRequest = ServletAccess.getRequest();
      if (servletRequest == null) {
        LOG.warn("HttpServletRequest is null. BasicAuthLoginModule will be ignored.");
        return false;
      }
      String authorization = servletRequest.getHeader("Authorization");
      if (servletRequest.getRemoteUser() == null &&
          (servletRequest.getRequestURI().startsWith("/portal/rest/")
          || servletRequest.getRequestURI().startsWith("/rest/"))
          && authorization != null
          && authorization.toLowerCase().startsWith("basic")) {

        // Authorization: Basic base64credentials
        String base64Credentials = authorization.substring("Basic".length()).trim();
        byte[] credDecoded = Base64.getDecoder().decode(base64Credentials);
        String credentialsString = new String(credDecoded);
        // credentials = username:password
        final String[] values = credentialsString.split(":", 2);
        String username = values[0];
        String password = values[1];

        if (username != null) {
          Authenticator authenticator = getContainer().getComponentInstanceOfType(Authenticator.class);
          if (authenticator == null) {
            throw new LoginException("No Authenticator component found, check your configuration");
          }
          Credential[] credentials =
              new Credential[] { new UsernameCredential(username), new PasswordCredential(password) };
          if (authenticator.validateUser(credentials) != null) {
            LOG.info("API Basic Auth successful");
            identity = authenticator.createIdentity(username);
            sharedState.put("javax.security.auth.login.name", username);
            sharedState.put("exo.security.identity", identity);
            subject.getPublicCredentials().add(new UsernameCredential(username));
            return true;
          }
        }
      }
    } catch(Exception e){
      throw new LoginException(e.getMessage());
    }
    return false;
  }
}
