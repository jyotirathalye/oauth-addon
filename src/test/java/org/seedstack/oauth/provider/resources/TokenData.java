/*
 * Copyright © 2013-2017, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.seedstack.oauth.provider.resources;

import java.util.ArrayList;
import java.util.List;

public class TokenData {
    
    String access_token;
    String token_type;
    int expires_in;
    String id_token;
    String scope;
    //List<String> scope = new ArrayList<String>();
    private boolean buildonlyAccessToken;
    
    public boolean getOnlyAccessToken() {
        return buildonlyAccessToken;
    }


    public void buildonlyAccessToken(boolean buildonlyAccessToken) {
        this.buildonlyAccessToken = buildonlyAccessToken;
    }
    
   public String getScope() {
        return scope;
    }
    public void setScope(String scope) {
        this.scope= scope;
    }
    public String getAccess_token() {
        return access_token;
    }
    public void setAccess_token(String access_token) {
        this.access_token = access_token;
    }
    public String getToken_type() {
        return token_type;
    }
    public void setToken_type(String token_type) {
        this.token_type = token_type;
    }
    public int getExpires_in() {
        return expires_in;
    }
    public void setExpires_in(int expires_in) {
        this.expires_in = expires_in;
    }
    public String getId_token() {
        return id_token;
    }
    public void setId_token(String id_token) {
        this.id_token = id_token;
    }
    

}
