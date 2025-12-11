/*
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.tokenprocessor;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.OAuth2Constants;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.OIDCClaimUtil;

import java.sql.Timestamp;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * Default implementation of @RefreshTokenGrantProcessor responsible for handling refresh token persistence logic.
 */
public class DefaultRefreshTokenGrantProcessor implements RefreshTokenGrantProcessor {

    private static final Log LOG = LogFactory.getLog(DefaultRefreshTokenGrantProcessor.class);
    private static final int LAST_ACCESS_TOKEN_RETRIEVAL_LIMIT = 10;

    @Override
    public RefreshTokenValidationDataDO validateRefreshToken(OAuthTokenReqMessageContext tokenReqMessageContext)
            throws IdentityOAuth2Exception {

        OAuth2AccessTokenReqDTO tokenReq = tokenReqMessageContext.getOauth2AccessTokenReqDTO();
        RefreshTokenValidationDataDO validationBean = OAuthTokenPersistenceFactory.getInstance().getTokenManagementDAO()
                .validateRefreshToken(tokenReq.getClientId(), tokenReq.getRefreshToken());
        validatePersistedAccessToken(validationBean, tokenReq.getClientId());
        return validationBean;
    }

    @Override
    public void persistNewToken(OAuthTokenReqMessageContext tokenReqMessageContext, AccessTokenDO accessTokenBean,
                                String userStoreDomain, String clientId) throws IdentityOAuth2Exception {

        // Retrieve the previously issued access token from the request context (used for rotation scenarios)
        RefreshTokenValidationDataDO oldAccessToken =
                (RefreshTokenValidationDataDO) tokenReqMessageContext.getProperty(OAuth2Constants.PREV_ACCESS_TOKEN);

        if (LOG.isDebugEnabled() && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                LOG.debug(String.format("Previous access token (hashed): %s", DigestUtils.sha256Hex(
                        oldAccessToken.getAccessToken())));
        }
        // set the previous access token state to "INACTIVE" and store new access token in single db connection
        OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAOImpl(clientId)
                .invalidateAndCreateNewAccessToken(oldAccessToken.getTokenId(),
                        OAuthConstants.TokenStates.TOKEN_STATE_INACTIVE, clientId,
                        UUID.randomUUID().toString(), accessTokenBean, userStoreDomain, oldAccessToken.getGrantType());
    }

    @Override
    public AccessTokenDO createAccessTokenBean(OAuthTokenReqMessageContext tokReqMsgCtx,
                                               OAuth2AccessTokenReqDTO tokenReq,
                                               RefreshTokenValidationDataDO validationBean, String tokenType)
            throws IdentityOAuth2Exception {

        Timestamp timestamp = new Timestamp(new Date().getTime());
        String tokenId = UUID.randomUUID().toString();

        AccessTokenDO accessTokenDO = new AccessTokenDO();
        accessTokenDO.setConsumerKey(tokenReq.getClientId());
        accessTokenDO.setAuthzUser(tokReqMsgCtx.getAuthorizedUser());
        accessTokenDO.setScope(tokReqMsgCtx.getScope());
        accessTokenDO.setTokenType(tokenType);
        accessTokenDO.setTokenState(OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);
        accessTokenDO.setTokenId(tokenId);
        accessTokenDO.setGrantType(tokenReq.getGrantType());
        accessTokenDO.setIssuedTime(timestamp);
        accessTokenDO.setTokenBinding(tokReqMsgCtx.getTokenBinding());

        if (OAuth2ServiceComponentHolder.isConsentedTokenColumnEnabled()) {
            String previousGrantType = validationBean.getGrantType();
            // Check if the previous grant type is consent refresh token type or not.
            if (!StringUtils.equals(OAuthConstants.GrantTypes.REFRESH_TOKEN, previousGrantType)) {
                // If the previous grant type is not a refresh token, then check if it's a consent token or not.
                if (OIDCClaimUtil.isConsentBasedClaimFilteringApplicable(previousGrantType)) {
                    accessTokenDO.setIsConsentedToken(true);
                }
            } else {
                /* When previousGrantType == refresh_token, we need to check whether the original grant type
                 is consented or not. */
                AccessTokenDO accessTokenDOFromTokenIdentifier = OAuth2Util.getAccessTokenDOFromTokenIdentifier(
                        validationBean.getAccessToken(), false);
                accessTokenDO.setIsConsentedToken(accessTokenDOFromTokenIdentifier.isConsentedToken());
            }

            if (accessTokenDO.isConsentedToken()) {
                tokReqMsgCtx.setConsentedToken(true);
            }
        }

        return accessTokenDO;
    }

    /**
     * Validates the presence of a persisted access token associated with the given refresh token.
     *
     * @param validationBean The data object containing access token information retrieved from persistence.
     * @param clientId       The client ID for which the refresh token was issued.
     * @throws IdentityOAuth2Exception if the persisted access token is missing.
     */
    private void validatePersistedAccessToken(RefreshTokenValidationDataDO validationBean, String clientId)
            throws IdentityOAuth2Exception {

        if (validationBean.getAccessToken() == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(String.format("Invalid Refresh Token provided for Client with Client Id : %s", clientId));
            }
            throw new IdentityOAuth2Exception("Persisted access token data not found");
        }
    }

    @Override
    public boolean isLatestRefreshToken(OAuth2AccessTokenReqDTO tokenReq, RefreshTokenValidationDataDO validationBean,
                                        String userStoreDomain) throws IdentityOAuth2Exception {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Evaluating refresh token. Token value: " + tokenReq.getRefreshToken() + ", Token state: " +
                    validationBean.getRefreshTokenState());
        }
        if (!OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE.equals(validationBean.getRefreshTokenState())) {
            /* if refresh token is not in active state, check whether there is an access token issued with the same
             * refresh token.
             */
            List<AccessTokenDO> accessTokenBeans = getAccessTokenBeans(tokenReq, validationBean, userStoreDomain);
            for (AccessTokenDO token : accessTokenBeans) {
                if (tokenReq.getRefreshToken() != null && tokenReq.getRefreshToken().equals(token.getRefreshToken())
                        && (OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE.equals(token.getTokenState())
                        || OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED.equals(token.getTokenState()))) {
                    return true;
                }
            }
            if (LOG.isDebugEnabled()) {
                LOG.debug(String.format("Refresh token: %s is not the latest", tokenReq.getRefreshToken()));
            }
            return false;
        }
        return true;
    }

    private List<AccessTokenDO> getAccessTokenBeans(OAuth2AccessTokenReqDTO tokenReq,
                                                    RefreshTokenValidationDataDO validationBean, String userStoreDomain)
            throws IdentityOAuth2Exception {

        List<AccessTokenDO> accessTokenBeans = OAuthTokenPersistenceFactory.getInstance()
                .getAccessTokenDAOImpl(tokenReq.getClientId())
                .getLatestAccessTokens(tokenReq.getClientId(), validationBean.getAuthorizedUser(), userStoreDomain,
                        OAuth2Util.buildScopeString(validationBean.getScope()),
                        validationBean.getTokenBindingReference(), true,
                        LAST_ACCESS_TOKEN_RETRIEVAL_LIMIT);
        if (accessTokenBeans == null || accessTokenBeans.isEmpty()) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(String.format("No previous access tokens found. User: %s, client: %s, scope: %s",
                        validationBean.getAuthorizedUser(), tokenReq.getClientId(),
                        OAuth2Util.buildScopeString(validationBean.getScope())));
            }
            throw new IdentityOAuth2Exception("No previous access tokens found");
        }
        return accessTokenBeans;
    }

    /**
     * Transfers user attributes cached against the previous access token to the new access token.
     *
     * <p>This is typically used during refresh token grant flows where a new access token is issued
     * and the cached user attributes (such as roles, claims, etc.) associated with the old access token
     * should be retained for the new one.</p>
     *
     * <p>This method also clears the old cache entry to avoid stale data and updates the validity period
     * of the cache entry to reflect the new token's lifetime.</p>
     *
     * @param accessTokenBean The newly issued access token object.
     * @param msgCtx          The token request message context, which may contain the previous access token.
     */
    public void addUserAttributesToCache(AccessTokenDO accessTokenBean, OAuthTokenReqMessageContext msgCtx) {

        // Retrieve the old access token from the message context (used during token rotation).
        RefreshTokenValidationDataDO oldAccessToken =
                (RefreshTokenValidationDataDO) msgCtx.getProperty(OAuth2Constants.PREV_ACCESS_TOKEN);

        AuthorizationGrantCacheKey oldAuthorizationGrantCacheKey = null;

        if (oldAccessToken.getAccessToken() != null) {
            // Construct cache key using the old access token. Used in Persistence Scenarios.
            oldAuthorizationGrantCacheKey = new AuthorizationGrantCacheKey(oldAccessToken.getAccessToken());
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Getting AuthorizationGrantCacheEntry using access token id: "
                    + accessTokenBean.getTokenId());
        }

        // Retrieve cached user attributes using the old token ID.
        AuthorizationGrantCacheEntry grantCacheEntry = AuthorizationGrantCache.getInstance()
                .getValueFromCacheByTokenId(oldAuthorizationGrantCacheKey, oldAccessToken.getTokenId());

        if (grantCacheEntry != null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Getting user attributes cached against the previous access token with access token id: " +
                        oldAccessToken.getTokenId());
            }

            // Create a new cache key for the new access token.
            AuthorizationGrantCacheKey newAuthorizationGrantCacheKey = new AuthorizationGrantCacheKey(accessTokenBean
                    .getAccessToken());

            // Update the token ID in the cache entry (null-safe).
            if (StringUtils.isNotBlank(accessTokenBean.getTokenId())) {
                grantCacheEntry.setTokenId(accessTokenBean.getTokenId());
            } else {
                grantCacheEntry.setTokenId(null);
            }

            // Update the validity period in nanoseconds.
            grantCacheEntry.setValidityPeriod(
                    TimeUnit.MILLISECONDS.toNanos(accessTokenBean.getValidityPeriodInMillis()));

            // Clear the old cache entry and add the updated entry under the new access token.
            AuthorizationGrantCache.getInstance().clearCacheEntryByTokenId(oldAuthorizationGrantCacheKey,
                    oldAccessToken.getTokenId());
            // If refresh token persistence is disabled and the user is not federated, do not store user attributes.
            // When a user's profile is updated after the token is issued, the cache cannot be cleared because
            // the Identity Server will not persist either the refresh token or the access token. As a result,
            // outdated user attribute data would be returned on the next refresh grant.
            // To mitigate this, user attributes are set to null.
            if (!OAuth2Util.isRefreshTokenPersistenceEnabled() && !accessTokenBean.getAuthzUser().isFederatedUser()) {
                grantCacheEntry.setUserAttributes(null);
            }
            AuthorizationGrantCache.getInstance().addToCacheByToken(newAuthorizationGrantCacheKey,
                    grantCacheEntry);
        }
    }
}
