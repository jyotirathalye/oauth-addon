/*
 * Copyright © 2013-2017, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package org.seedstack.oauth;

import static org.junit.Assert.assertNotNull;

import java.net.URL;

import javax.inject.Inject;

import org.apache.shiro.authc.AuthenticationToken;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.Test;
import org.seedstack.seed.it.AbstractSeedWebIT;

public class OAuthClientCredsFlowIT extends AbstractSeedWebIT{

    @Inject
    private OAuthService oauthService;
    
    
    @ArquillianResource
    private URL baseURL;

    @Deployment
    public static WebArchive createDeployment() {
        return ShrinkWrap.create(WebArchive.class);
    }
    
    
    @Test
    @RunAsClient
    public void method_should_return_authentication_token(){
        assertNotNull(oauthService.getTokenFromClientCredentials());
    }
    
}
