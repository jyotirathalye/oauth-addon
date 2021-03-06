/*
 * Copyright © 2013-2017, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.seedstack.oauth.provider.resources;

import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import org.seedstack.oauth.OAuthConfig;
import org.seedstack.seed.Configuration;


@Path("/provider/create-token")
public class TokenResource {
    
    @Configuration("testConfig.testInvalidAudience")
    private boolean testInvalidAudience;
      
    @Configuration("testConfig.testTokenExpiry")
    private boolean testTokenExpiry;
    
    @Configuration("testConfig.testInvalidNonce")
    private boolean testInvalidNonce;
    
    @Configuration
    private OAuthConfig oauthConfig;
    
    @Configuration("fetchOnlyAccessToken")
    private boolean buildOnlyAccessToken;
    
    
    @POST
    @Produces(MediaType.APPLICATION_JSON)
    public Response createttoken(){

        NonceHandler n = new NonceHandler();
        String nonce = n.getNonce();
        n.deleteFile();
       
        return Response.ok(tokenData(nonce)).build();
    }
    
    private TokenData tokenData(String nonce){
        TokenBuilder tb = new TokenBuilder();
        tb.setTestInvalidNonce(testInvalidNonce);
        tb.setTestInvalidAudience(testInvalidAudience);
        tb.setTestTokenExpiry(testTokenExpiry);
        tb.setTestClientId(oauthConfig.getClientId());
        tb.setFlagForAccessToken(buildOnlyAccessToken);
        return tb.buildToken(nonce,oauthConfig.getScopes());
    }
    
}
