/*
 * Copyright © 2013-2017, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package org.seedstack.oauth.internal;

import static com.google.common.base.Preconditions.checkNotNull;

import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import java.net.URI;
import java.util.List;
import java.util.Optional;
import org.seedstack.oauth.OAuthConfig;
import org.seedstack.oauth.OAuthProvider;
import org.seedstack.seed.SeedException;

class DiscoveredOAuthProvider implements OAuthProvider {
    private final OAuthConfig oauthConfig;
    private final DiscoveryDocument oidcDiscoveryDocument;

    DiscoveredOAuthProvider(OAuthConfig oauthConfig, DiscoveryDocument oidcDiscoveryDocument) {
        this.oauthConfig = oauthConfig;
        this.oidcDiscoveryDocument = oidcDiscoveryDocument;
    }

    @Override
    public boolean isOpenIdCapable() {
        List<String> scopesSupported = oidcDiscoveryDocument.getScopesSupported();
        return oauthConfig.openIdConnect().isEnabled()
                && scopesSupported != null
                && scopesSupported.contains(OIDCScopeValue.OPENID.getValue());
    }

    @Override
    public Optional<URI> getIssuer() {
        return Optional.ofNullable(oidcDiscoveryDocument.getIssuer());
    }

    @Override
    public URI getAuthorizationEndpoint() {
        return checkNotNull(oidcDiscoveryDocument.getAuthorizationEndpoint(),
                "Authorization endpoint should not be null");
    }

    @Override
    public URI getTokenEndpoint() {
        return checkNotNull(oidcDiscoveryDocument.getTokenEndpoint(), "Token endpoint should not be null");
    }

    @Override
    public Optional<URI> getUserInfoEndpoint() {
        return Optional.ofNullable(oidcDiscoveryDocument.getUserinfoEndpoint());
    }

    @Override
    public Optional<URI> getRevocationEndpoint() {
        return Optional.ofNullable(oidcDiscoveryDocument.getRevocationEndpoint());
    }

    @Override
    public Optional<URI> getJwksEndpoint() {
        return Optional.ofNullable(oidcDiscoveryDocument.getJwksUri());
    }

    @Override
    public String getSigningAlgorithm() {
        List<String> supportedAlgorithms = oidcDiscoveryDocument.getIdTokenSigningAlgValuesSupported();
        String signingAlgorithm = checkNotNull(oauthConfig.openIdConnect().getSigningAlgorithm(),
                "Expected algorithm not configured");
        if (!supportedAlgorithms.contains(signingAlgorithm)) {
            throw SeedException.createNew(OAuthErrorCode.SIGNING_ALGORITHM_NOT_SUPPORTED_BY_PROVIDER)
                    .put("requiredAlgorithm", signingAlgorithm)
                    .put("supportedAlgorithms", String.valueOf(supportedAlgorithms));

        }
        return signingAlgorithm;
    }
}
