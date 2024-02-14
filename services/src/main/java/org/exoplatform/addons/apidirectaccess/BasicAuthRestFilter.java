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

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.exoplatform.container.ExoContainerContext;
import org.exoplatform.container.web.AbstractFilter;
import org.gatein.wci.ServletContainer;
import org.gatein.wci.ServletContainerFactory;
import org.gatein.wci.security.Credentials;

import java.io.IOException;

/**
 * The basicAuthRest filter performs an authentication using the
 * {@link ServletContainer} when the user is not authenticated and
 * when the request is a rest call and
 * when there is a Authorization header

 */
public class BasicAuthRestFilter extends AbstractFilter {


  public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain) throws IOException, ServletException {
    HttpServletRequest request = (HttpServletRequest) req;
    HttpServletResponse response = (HttpServletResponse) resp;
    ExoContainerContext.setCurrentContainer(getContainer());
    String authorization = request.getHeader("Authorization");
    if (request.getRemoteUser() == null &&
        (request.getRequestURI().startsWith("/portal/rest/")
            || request.getRequestURI().startsWith("/rest/"))
        && authorization != null
        && authorization.toLowerCase().startsWith("basic")) {
      ServletContainer servletContainer = ServletContainerFactory.getServletContainer();
      Credentials credentials = new Credentials("","");
      servletContainer.login(request, response, credentials);
    }

    // Continue
    chain.doFilter(request, response);
  }
}
