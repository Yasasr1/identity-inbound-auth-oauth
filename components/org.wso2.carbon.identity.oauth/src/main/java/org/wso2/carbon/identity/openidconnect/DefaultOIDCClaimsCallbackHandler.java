/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wso2.carbon.identity.openidconnect;

import com.nimbusds.jwt.JWTClaimsSet;
import net.minidev.json.JSONArray;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataHandler;
import org.wso2.carbon.identity.claim.metadata.mgt.exception.ClaimMetadataException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.RequestObjectException;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.device.cache.DeviceAuthorizationGrantCache;
import org.wso2.carbon.identity.oauth2.device.cache.DeviceAuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth2.device.cache.DeviceAuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.identity.oauth2.token.AccessTokenIssuer;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuer;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.RefreshGrantHandler;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.internal.OpenIDConnectServiceComponentHolder;
import org.wso2.carbon.identity.openidconnect.model.RequestedClaim;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.user.api.Tenant;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.common.User;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;

import static org.apache.commons.collections.MapUtils.isEmpty;
import static org.apache.commons.collections.MapUtils.isNotEmpty;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.ACCESS_TOKEN;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.AUTHZ_CODE;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.ID_TOKEN;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDCClaims.ADDRESS;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDCClaims.GROUPS;
import static org.wso2.carbon.identity.oauth2.device.constants.Constants.DEVICE_CODE;

/**
 * Default implementation of {@link CustomClaimsCallbackHandler}. This callback handler populates available user
 * claims after filtering them through requested scopes using {@link OpenIDConnectClaimFilter}.
 */
public class DefaultOIDCClaimsCallbackHandler implements CustomClaimsCallbackHandler {

    private static final Log log = LogFactory.getLog(DefaultOIDCClaimsCallbackHandler.class);
    private static final String OAUTH2 = "oauth2";
    private static final String OIDC_DIALECT = "http://wso2.org/oidc/claim";
    private static final String ATTRIBUTE_SEPARATOR = FrameworkUtils.getMultiAttributeSeparator();

    @Override
    public JWTClaimsSet handleCustomClaims(JWTClaimsSet.Builder jwtClaimsSetBuilder, OAuthTokenReqMessageContext
            tokenReqMessageContext) throws IdentityOAuth2Exception {
        try {
            Map<String, Object> userClaimsInOIDCDialect = getUserClaimsInOIDCDialect(tokenReqMessageContext);
            return setClaimsToJwtClaimSet(jwtClaimsSetBuilder, userClaimsInOIDCDialect);
        } catch (OAuthSystemException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error occurred while adding claims of user: " + tokenReqMessageContext.getAuthorizedUser() +
                        " to the JWTClaimSet used to build the id_token.", e);
            }
        }
        return null;
    }

    @Override
    public JWTClaimsSet handleCustomClaims(JWTClaimsSet.Builder jwtClaimsSet,
                                           OAuthAuthzReqMessageContext authzReqMessageContext)
            throws IdentityOAuth2Exception {

        try {
            Map<String, Object> userClaimsInOIDCDialect = getUserClaimsInOIDCDialect(authzReqMessageContext);
            return setClaimsToJwtClaimSet(jwtClaimsSet, userClaimsInOIDCDialect);
        } catch (OAuthSystemException e) {
            log.error("Error occurred while adding claims of user: " +
                    authzReqMessageContext.getAuthorizationReqDTO().getUser() + " to the JWTClaimSet used to " +
                    "build the id_token.", e);
        }
        return null;
    }

    /**
     * Filter user claims based on the OIDC Scopes defined at server level.
     *
     * @param requestedScopes             Requested Scopes in the OIDC Request
     * @param serviceProviderTenantDomain Tenant domain of the service provider
     * @param userClaims                  Map of user claims
     * @return
     */
    protected Map<String, Object> filterClaimsByScope(Map<String, Object> userClaims,
                                                      String[] requestedScopes,
                                                      String clientId,
                                                      String serviceProviderTenantDomain) {
        return OpenIDConnectServiceComponentHolder.getInstance()
                .getHighestPriorityOpenIDConnectClaimFilter()
                .getClaimsFilteredByOIDCScopes(userClaims, requestedScopes, clientId, serviceProviderTenantDomain);
    }

    /**
     * Get response map.
     *
     * @param requestMsgCtx Token request message context
     * @return Mapped claimed
     * @throws OAuthSystemException
     */
    private Map<String, Object> getUserClaimsInOIDCDialect(OAuthTokenReqMessageContext requestMsgCtx)
            throws OAuthSystemException, IdentityOAuth2Exception {
        // Map<"email", "peter@example.com">
        Map<String, Object> userClaimsInOIDCDialect;
        // Get any user attributes that were cached against the access token
        // Map<(http://wso2.org/claims/email, email), "peter@example.com">
        Map<ClaimMapping, String> userAttributes = getCachedUserAttributes(requestMsgCtx);
        if (isEmpty(userAttributes) && isLocalUser(requestMsgCtx.getAuthorizedUser())) {
            if (log.isDebugEnabled()) {
                log.debug("User attributes not found in cache against the access token or authorization code. " +
                        "Retrieving claims for local user: " + requestMsgCtx.getAuthorizedUser() + " from userstore.");
            }
            // Get claim in oidc dialect from user store.
            userClaimsInOIDCDialect = retrieveClaimsForLocalUser(requestMsgCtx);
        } else {
            // Get claim map from the cached attributes
            userClaimsInOIDCDialect = getOIDCClaimsFromUserAttributes(userAttributes, requestMsgCtx);
        }

        Object hasNonOIDCClaimsProperty = requestMsgCtx.getProperty(OIDCConstants.HAS_NON_OIDC_CLAIMS);
        if (isPreserverClaimUrisInAssertion(requestMsgCtx) || (hasNonOIDCClaimsProperty != null
                && (Boolean) hasNonOIDCClaimsProperty)) {
            return userClaimsInOIDCDialect;
        } else {
            return filterOIDCClaims(requestMsgCtx, userClaimsInOIDCDialect);
        }
    }

    private Map<String, Object> filterOIDCClaims(OAuthTokenReqMessageContext requestMsgCtx,
                                                 Map<String, Object> userClaimsInOIDCDialect)
            throws OAuthSystemException {

        AuthenticatedUser user = requestMsgCtx.getAuthorizedUser();
        String clientId = requestMsgCtx.getOauth2AccessTokenReqDTO().getClientId();
        String spTenantDomain = requestMsgCtx.getOauth2AccessTokenReqDTO().getTenantDomain();
        String[] approvedScopes = requestMsgCtx.getScope();
        String token = getAccessToken(requestMsgCtx);
        String authorizationCode = getAuthorizationCode(requestMsgCtx);
        String grantType = requestMsgCtx.getOauth2AccessTokenReqDTO().getGrantType();
        // Get the flag which has the record whether the token is a consented one or not.
        boolean isConsentedToken = false;
        if (requestMsgCtx.isConsentedToken()) {
            isConsentedToken = requestMsgCtx.isConsentedToken();
        }

        return filterOIDCClaims(token, authorizationCode, grantType, userClaimsInOIDCDialect, user,
                approvedScopes, clientId, spTenantDomain, isConsentedToken);
    }


    private Map<String, Object> filterOIDCClaims(String accessToken,
                                                 String authorizationCode,
                                                 String grantType,
                                                 Map<String, Object> userClaimsInOIDCDialect,
                                                 AuthenticatedUser authenticatedUser,
                                                 String[] approvedScopes,
                                                 String clientId,
                                                 String spTenantDomain,
                                                 boolean isConsentedToken) throws OAuthSystemException {
        Map<String, Object> filteredUserClaimsByOIDCScopes =
                filterClaimsByScope(userClaimsInOIDCDialect, approvedScopes, clientId, spTenantDomain);

        /*
         * Add the essential claims from the authorization grant cache if any.
         * This will be used for the request object flow where essential claims are requested.
         */
        Map<String, Object> essentialClaims = getEssentialClaims(accessToken, userClaimsInOIDCDialect);
        filteredUserClaimsByOIDCScopes.putAll(essentialClaims);

        if (accessToken != null) {
            if (StringUtils.isNotBlank(authorizationCode)) {
                AuthorizationGrantCacheKey cacheKey = new AuthorizationGrantCacheKey(authorizationCode);
                AuthorizationGrantCacheEntry cacheEntry =
                        AuthorizationGrantCache.getInstance().getValueFromCacheByCode(cacheKey);
                if (cacheEntry != null && cacheEntry.isRequestObjectFlow()) {
                    // Handle essential claims of the request object
                    Map<String, Object> claimsFromRequestObject =
                            filterClaimsFromRequestObject(userClaimsInOIDCDialect, accessToken);
                    filteredUserClaimsByOIDCScopes.putAll(claimsFromRequestObject);
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("The request does not contains request object. So skipping " +
                                "filterClaimsFromRequestObject");
                    }
                }
            }
        }

        // Restrict the claims based on user consent given
        return getUserConsentedClaims(filteredUserClaimsByOIDCScopes, authenticatedUser, grantType, clientId,
                spTenantDomain, isConsentedToken);
    }

    private Map<String, Object> getEssentialClaims(String accessToken, Map<String, Object> claims) {

        Map<String, Object> essentialClaimMap = new HashMap<>();
        List<String> essentialClaims = getEssentialClaimUris(accessToken);
        if (CollectionUtils.isNotEmpty(essentialClaims)) {
            for (String key : essentialClaims) {
                essentialClaimMap.put(key, claims.get(key));
            }
        }
        return essentialClaimMap;
    }

    private List<String> getEssentialClaimUris(String accessToken) {

        AuthorizationGrantCacheKey cacheKey = new AuthorizationGrantCacheKey(accessToken);
        AuthorizationGrantCacheEntry cacheEntry = AuthorizationGrantCache.getInstance()
                .getValueFromCacheByToken(cacheKey);

        if (cacheEntry != null) {
            if (StringUtils.isNotEmpty(cacheEntry.getEssentialClaims())) {
                return OAuth2Util.getEssentialClaims(cacheEntry.getEssentialClaims(), ID_TOKEN);
            }
        }

        return new ArrayList<>();
    }

    private boolean isPreserverClaimUrisInAssertion(OAuthTokenReqMessageContext requestMsgCtx) {

        return !OAuthServerConfiguration.getInstance().isConvertOriginalClaimsFromAssertionsToOIDCDialect() &&
                requestMsgCtx.getAuthorizedUser().isFederatedUser();
    }

    private Map<String, Object> filterClaimsFromRequestObject(Map<String, Object> userAttributes,
                                                              String token) throws OAuthSystemException {

        try {
            List<RequestedClaim> requestedClaims = OpenIDConnectServiceComponentHolder.getRequestObjectService().
                    getRequestedClaimsForIDToken(token);
            return OpenIDConnectServiceComponentHolder.getInstance()
                    .getHighestPriorityOpenIDConnectClaimFilter()
                    .getClaimsFilteredByEssentialClaims(userAttributes, requestedClaims);
        } catch (RequestObjectException e) {
            throw new OAuthSystemException("Unable to retrieve requested claims from Request Object." + e);
        }
    }

    private Map<String, Object> getUserConsentedClaims(Map<String, Object> userClaims,
                                                       AuthenticatedUser authenticatedUser,
                                                       String grantType,
                                                       String clientId,
                                                       String spTenantDomain,
                                                       boolean isConsentedToken) throws OAuthSystemException {

        ServiceProvider serviceProvider;
        try {
            serviceProvider = getServiceProvider(spTenantDomain, clientId);
        } catch (IdentityApplicationManagementException e) {
            throw new OAuthSystemException(
                    "Error while obtaining service provider for tenant domain: " + spTenantDomain + " client id: "
                            + clientId, e);
        }

        return OIDCClaimUtil.filterUserClaimsBasedOnConsent(userClaims, authenticatedUser, clientId,
                spTenantDomain, grantType, serviceProvider, isConsentedToken);
    }

    /**
     * This method retrieves the user attributes cached against the access token or the authorization code.
     * Currently, this is supported for the code grant and the refresh grant.
     *
     * @param requestMsgCtx The context of the OAuth token request containing necessary properties.
     * @return A map of cached user attributes against the code or the access token.
     * @throws OAuthSystemException    If there is an error while generating the access token hash.
     * @throws IdentityOAuth2Exception If an error occurs while selecting the OAuth2 token issuer.
     */
    private Map<ClaimMapping, String> getCachedUserAttributes(OAuthTokenReqMessageContext requestMsgCtx)
            throws OAuthSystemException, IdentityOAuth2Exception {

        Map<ClaimMapping, String> userAttributes = getUserAttributesCachedAgainstToken(getAccessToken(requestMsgCtx));
        if (log.isDebugEnabled()) {
            log.debug("Retrieving claims cached against access_token for user: " + requestMsgCtx.getAuthorizedUser());
        }
        if (isEmpty(userAttributes)) {
            if (log.isDebugEnabled()) {
                log.debug("No claims cached against the access_token for user: " + requestMsgCtx.getAuthorizedUser() +
                        ". Retrieving claims cached against the authorization code.");
            }
            userAttributes = getUserAttributesCachedAgainstAuthorizationCode(getAuthorizationCode(requestMsgCtx));
            if (log.isDebugEnabled()) {
                log.debug("Retrieving claims cached against authorization_code for user: " +
                        requestMsgCtx.getAuthorizedUser());
            }
        }

        // Check for claims cached against the device code.
        if (isEmpty(userAttributes)) {
            if (log.isDebugEnabled()) {
                log.debug("No claims cached against the authorization_code for user: " +
                        requestMsgCtx.getAuthorizedUser() + ". Retrieving claims cached against the device code.");
            }
            userAttributes = getUserAttributesCachedAgainstDeviceCode(getDeviceCode(requestMsgCtx));
        }
        /* When building the jwt token, we cannot add it to authorization cache, as we save entries against, access
         token. Hence if it is added against authenticated user object.*/
        if (isEmpty(userAttributes)) {
            if (log.isDebugEnabled()) {
                log.debug("No claims found in authorization cache. Retrieving claims from attributes of user : " +
                        requestMsgCtx.getAuthorizedUser());
            }
            AuthenticatedUser user = requestMsgCtx.getAuthorizedUser();
            userAttributes = user != null ? user.getUserAttributes() : null;
        }
         // In the refresh flow, we need to follow the same way to get the claims.
        if (isEmpty(userAttributes)) {
            if (log.isDebugEnabled()) {
                log.debug("No claims found in user in user attributes for user : " + requestMsgCtx.getAuthorizedUser());
            }

             /*
            The purpose of this segment is retrieving the user attributes at the refresh grant while the caches
            are disabled. The code/token acts as the key in cache layer while access token hash acts as the key for
            entries in the persistence layer(SessionStore).
            At this point, the token indicated by RefreshGrantHandler.PREV_ACCESS_TOKEN is no longer
            present in the caches or the persistence layer because a new access token has already been generated
            and added to the cache with new token references. However, RefreshGrantHandler.PREV_ACCESS_TOKEN cannot
            yet be replaced with the new access token since the refresh token has not been generated, and
            the new token is not yet considered "previous" by definition.
             */
            String latestAccessTokenHash = getLatestAccessTokenHash(requestMsgCtx);
            if (StringUtils.isNotBlank(latestAccessTokenHash)) {
                userAttributes = getUserAttributesCachedAgainstToken(latestAccessTokenHash);
            }

            Object previousAccessTokenObject = requestMsgCtx.getProperty(RefreshGrantHandler.PREV_ACCESS_TOKEN);

            if (previousAccessTokenObject != null) {
                if (log.isDebugEnabled()) {
                    log.debug("Retrieving claims from previous access token of user : " + requestMsgCtx
                            .getAuthorizedUser());
                }
                RefreshTokenValidationDataDO refreshTokenValidationDataDO =
                        (RefreshTokenValidationDataDO) previousAccessTokenObject;
                userAttributes = getUserAttributesCachedAgainstToken(refreshTokenValidationDataDO.getAccessToken());
                requestMsgCtx.addProperty(OIDCConstants.HAS_NON_OIDC_CLAIMS,
                        isTokenHasCustomUserClaims(refreshTokenValidationDataDO));
            }
        }
        return userAttributes;
    }

    private Map<String, Object> retrieveClaimsForLocalUser(OAuthTokenReqMessageContext requestMsgCtx)
            throws IdentityOAuth2Exception {

        try {
            String spTenantDomain = getServiceProviderTenantDomain(requestMsgCtx);
            String clientId = requestMsgCtx.getOauth2AccessTokenReqDTO().getClientId();
            AuthenticatedUser authenticatedUser = requestMsgCtx.getAuthorizedUser();

            return getUserClaimsInOIDCDialect(spTenantDomain, clientId, authenticatedUser);
        } catch (UserStoreException | IdentityApplicationManagementException | IdentityException |
                 OrganizationManagementException e) {
            if (FrameworkUtils.isContinueOnClaimHandlingErrorAllowed()) {
                log.error("Error occurred while getting claims for user: " + requestMsgCtx.getAuthorizedUser() +
                        " from userstore.", e);
            } else {
                throw new IdentityOAuth2Exception("Error occurred while getting claims for user: " +
                        requestMsgCtx.getAuthorizedUser() + " from userstore.", e);
            }
        }
        return new HashMap<>();
    }

    private Map<ClaimMapping, String> getUserAttributesCachedAgainstAuthorizationCode(String authorizationCode) {
        Map<ClaimMapping, String> userAttributes = Collections.emptyMap();
        if (authorizationCode != null) {
            // Get the cached user claims against the authorization code if any.
            userAttributes = getUserAttributesFromCacheUsingCode(authorizationCode);
        }
        return userAttributes;
    }

    private Map<ClaimMapping, String> getUserAttributesCachedAgainstToken(String accessToken) {
        Map<ClaimMapping, String> userAttributes = Collections.emptyMap();
        if (accessToken != null) {
            // get the user claims cached against the access token if any
            userAttributes = getUserAttributesFromCacheUsingToken(accessToken);
        }
        return userAttributes;
    }

    private Map<ClaimMapping, String> getUserAttributesCachedAgainstDeviceCode(String deviceCode) {

        if (StringUtils.isEmpty(deviceCode)) {
            return Collections.emptyMap();
        }
        DeviceAuthorizationGrantCacheKey cacheKey = new DeviceAuthorizationGrantCacheKey(deviceCode);
        DeviceAuthorizationGrantCacheEntry cacheEntry =
                DeviceAuthorizationGrantCache.getInstance().getValueFromCache(cacheKey);
        return cacheEntry == null ? Collections.emptyMap() : cacheEntry.getUserAttributes();
    }

    private Map<String, Object> getUserClaimsInOIDCDialect(OAuthAuthzReqMessageContext authzReqMessageContext)
            throws OAuthSystemException, IdentityOAuth2Exception {

        Map<String, Object> userClaimsInOIDCDialect;
        Map<ClaimMapping, String> userAttributes =
                getUserAttributesCachedAgainstToken(getAccessToken(authzReqMessageContext));

        if (isEmpty(userAttributes)) {
            if (isLocalUser(authzReqMessageContext)) {
                if (log.isDebugEnabled()) {
                    log.debug("User attributes not found in cache. Trying to retrieve attribute from auth " +
                            "context for local user: " + authzReqMessageContext.getAuthorizationReqDTO().getUser());
                }
                userAttributes = authzReqMessageContext.getAuthorizationReqDTO().getUser()
                        .getUserAttributes();
                if (isEmpty(userAttributes)) {
                    if (log.isDebugEnabled()) {
                        log.debug("User attributes not found in auth context. Trying to retrieve attribute for " +
                                "local user: " + authzReqMessageContext.getAuthorizationReqDTO().getUser());
                    }
                    userClaimsInOIDCDialect = retrieveClaimsForLocalUser(authzReqMessageContext);
                } else {
                    userClaimsInOIDCDialect = getOIDCClaimMapFromUserAttributes(userAttributes);
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("User attributes not found in cache. Trying to retrieve attribute for federated " +
                            "user: " + authzReqMessageContext.getAuthorizationReqDTO().getUser());
                }
                userClaimsInOIDCDialect = retrieveClaimsForFederatedUser(authzReqMessageContext);
            }
        } else {
            userClaimsInOIDCDialect = getOIDCClaimMapFromUserAttributes(userAttributes);
        }

        return filterOIDCClaims(authzReqMessageContext, userClaimsInOIDCDialect);
    }

    /**
     * Retrieve the claim set of the AuthenticatedUser from the OAuthAuthzReqMessageContext.
     *
     * @param authzReqMessageContext OAuthAuthzReqMessageContext.
     * @return Map of user attributes.
     */
    private Map<String, Object> retrieveClaimsForFederatedUser(OAuthAuthzReqMessageContext authzReqMessageContext) {

        OAuth2AuthorizeReqDTO oAuth2AuthorizeReqDTO = authzReqMessageContext.getAuthorizationReqDTO();
        Map<String, Object> userClaimsMappedToOIDCDialect = new HashMap<>();

        if (oAuth2AuthorizeReqDTO == null) {
            if (log.isDebugEnabled()) {
                log.debug("OAuth2AuthorizeReqDTO is NULL for federated user: " +
                        authzReqMessageContext.getAuthorizationReqDTO().getUser());
            }
            return userClaimsMappedToOIDCDialect;
        }
        AuthenticatedUser authenticatedUser = oAuth2AuthorizeReqDTO.getUser();
        if (authenticatedUser == null) {
            if (log.isDebugEnabled()) {
                log.debug("Authenticated User is not available in the request");
            }
            return userClaimsMappedToOIDCDialect;
        }
        userClaimsMappedToOIDCDialect = getOIDCClaimMapFromUserAttributes(authenticatedUser.getUserAttributes());
        return userClaimsMappedToOIDCDialect;
    }

    private Map<String, Object> filterOIDCClaims(OAuthAuthzReqMessageContext authzReqMessageContext,
                                                 Map<String, Object> userClaimsInOIDCDialect)
            throws OAuthSystemException {

        AuthenticatedUser user = authzReqMessageContext.getAuthorizationReqDTO().getUser();
        String clientId = authzReqMessageContext.getAuthorizationReqDTO().getConsumerKey();
        String spTenantDomain = authzReqMessageContext.getAuthorizationReqDTO().getTenantDomain();
        String[] approvedScopes = authzReqMessageContext.getApprovedScope();
        String accessToken = getAccessToken(authzReqMessageContext);
        String grantType = OAuthConstants.GrantTypes.IMPLICIT;
        boolean isConsentedGrant = OIDCClaimUtil.isConsentBasedClaimFilteringApplicable(grantType);
        return filterOIDCClaims(accessToken, StringUtils.EMPTY, grantType, userClaimsInOIDCDialect, user,
                approvedScopes, clientId, spTenantDomain, isConsentedGrant);
    }

    private Map<String, Object> retrieveClaimsForLocalUser(OAuthAuthzReqMessageContext authzReqMessageContext)
            throws IdentityOAuth2Exception {

        try {
            String spTenantDomain = getServiceProviderTenantDomain(authzReqMessageContext);
            String clientId = authzReqMessageContext.getAuthorizationReqDTO().getConsumerKey();
            AuthenticatedUser authenticatedUser = authzReqMessageContext.getAuthorizationReqDTO().getUser();

            return getUserClaimsInOIDCDialect(spTenantDomain, clientId, authenticatedUser);
        } catch (UserStoreException | IdentityApplicationManagementException | IdentityException |
                 OrganizationManagementException e) {
            if (FrameworkUtils.isContinueOnClaimHandlingErrorAllowed()) {
                log.error("Error occurred while getting claims for user " +
                        authzReqMessageContext.getAuthorizationReqDTO().getUser(), e);
            } else {
                throw new IdentityOAuth2Exception("Error occurred while getting claims for user " +
                        authzReqMessageContext.getAuthorizationReqDTO().getUser(), e);
            }
        }
        return new HashMap<>();
    }

    /**
     * Get claims map.
     *
     * @param userAttributes User Attributes
     * @return User attribute map
     */
    private Map<String, Object> getOIDCClaimMapFromUserAttributes(Map<ClaimMapping, String> userAttributes) {

        Map<String, Object> claims = new HashMap<>();
        if (isNotEmpty(userAttributes)) {
            for (Map.Entry<ClaimMapping, String> entry : userAttributes.entrySet()) {
                claims.put(entry.getKey().getRemoteClaim().getClaimUri(), entry.getValue());
            }
        }
        return claims;
    }

    /**
     * Get oidc claims mapping.
     *
     * @param userAttributes    User attributes.
     * @param requestMsgCtx     Request Context.
     * @return User attributes Map.
     */
    private Map<String, Object> getOIDCClaimsFromUserAttributes(Map<ClaimMapping, String> userAttributes,
                                                                OAuthTokenReqMessageContext requestMsgCtx)
            throws IdentityOAuth2Exception {

        String spTenantDomain = getServiceProviderTenantDomain(requestMsgCtx);
        Map<String, String> claims = new HashMap<>();
        if (isNotEmpty(userAttributes)) {
            for (Map.Entry<ClaimMapping, String> entry : userAttributes.entrySet()) {
                claims.put(entry.getKey().getRemoteClaim().getClaimUri(), entry.getValue().toString());
            }
        }
        Map<String, Object> oidcClaims = new HashMap<>();
        try {
            oidcClaims = getUserClaimsInOIDCDialect(spTenantDomain, claims);
            // Merge the initial claims into oidcClaims, while prioritizing the initial claims map.
            for (Map.Entry<String, String> claimEntry : claims.entrySet()) {
                oidcClaims.put(claimEntry.getKey(), claimEntry.getValue());
            }
            return oidcClaims;
        } catch (ClaimMetadataException e) {
            throw new IdentityOAuth2Exception("Error occurred while mapping claims for user: " +
                    requestMsgCtx.getAuthorizedUser() + " from userstore.", e);
        }
    }

    private Map<String, Object> getUserClaimsInOIDCDialect(String spTenantDomain,
                                                           String clientId,
                                                           AuthenticatedUser authenticatedUser)
            throws IdentityApplicationManagementException, IdentityException, UserStoreException,
            OrganizationManagementException {

        Map<String, Object> userClaimsMappedToOIDCDialect = new HashMap<>();
        ServiceProvider serviceProvider = getServiceProvider(spTenantDomain, clientId);
        if (serviceProvider == null) {
            log.warn("Unable to find a service provider associated with client_id: " + clientId + " in tenantDomain: " +
                    spTenantDomain + ". Returning empty claim map for user.");
            return userClaimsMappedToOIDCDialect;
        }

        ClaimMapping[] requestClaimMappings = getRequestedClaimMappings(serviceProvider);
        if (ArrayUtils.isEmpty(requestClaimMappings)) {
            if (log.isDebugEnabled()) {
                String spName = serviceProvider.getApplicationName();
                log.debug("No requested claims configured for service provider: " + spName + " of tenantDomain: "
                        + spTenantDomain + ". No claims returned for user: " + authenticatedUser);
            }
            return userClaimsMappedToOIDCDialect;
        }
        String userTenantDomain;
        String fullQualifiedUsername;
        if (StringUtils.isNotBlank(authenticatedUser.getUserId())) {
            String userId = authenticatedUser.getUserId();
            userTenantDomain = authenticatedUser.getTenantDomain();
            int tenantId = IdentityTenantUtil.getTenantId(userTenantDomain);
            Tenant tenant =
                    OAuthComponentServiceHolder.getInstance().getRealmService().getTenantManager().getTenant(tenantId);
            if (tenant != null && StringUtils.isNotBlank(tenant.getAssociatedOrganizationUUID())) {
                Optional<User> user = OAuth2ServiceComponentHolder.getOrganizationUserResidentResolverService()
                        .resolveUserFromResidentOrganization(null, userId, tenant.getAssociatedOrganizationUUID());
                if (!user.isPresent()) {
                    return userClaimsMappedToOIDCDialect;
                }
                userTenantDomain = user.get().getTenantDomain();
                fullQualifiedUsername = user.get().getFullQualifiedUsername();
            } else {
                userTenantDomain = authenticatedUser.getTenantDomain();
                fullQualifiedUsername = authenticatedUser.toFullQualifiedUsername();
            }
        } else {
            userTenantDomain = authenticatedUser.getTenantDomain();
            fullQualifiedUsername = authenticatedUser.toFullQualifiedUsername();
        }
        UserRealm realm = IdentityTenantUtil.getRealm(userTenantDomain, fullQualifiedUsername);
        if (realm == null) {
            log.warn("Invalid tenant domain: " + userTenantDomain + " provided. Cannot get claims for user: "
                    + fullQualifiedUsername);
            return userClaimsMappedToOIDCDialect;
        }

        List<String> requestedClaimUris = getRequestedClaimUris(requestClaimMappings);
        // Improve runtime claim value storage in cache through https://github.com/wso2/product-is/issues/15056
        requestedClaimUris.removeIf(claim -> claim.startsWith("http://wso2.org/claims/runtime/"));
        Map<String, String> userClaims =
                getUserClaimsInLocalDialect(fullQualifiedUsername, realm, requestedClaimUris);

        if (isEmpty(userClaims)) {
            // User claims can be empty if user does not exist in user stores. Probably a federated user.
            if (log.isDebugEnabled()) {
                log.debug("No claims found for " + fullQualifiedUsername + " from user store.");
            }
            return userClaimsMappedToOIDCDialect;
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Number of user claims retrieved for " + fullQualifiedUsername + " from user store: " +
                        userClaims.size());
            }
            // Map the local roles to SP defined roles.
            handleServiceProviderRoleMappings(serviceProvider, ATTRIBUTE_SEPARATOR, userClaims);

            // Get the user claims in oidc dialect to be returned in the id_token.
            Map<String, Object> userClaimsInOIDCDialect = getUserClaimsInOIDCDialect(spTenantDomain, userClaims);
            userClaimsMappedToOIDCDialect.putAll(userClaimsInOIDCDialect);
        }

        return userClaimsMappedToOIDCDialect;
    }

    private ClaimMapping[] getRequestedClaimMappings(ServiceProvider serviceProvider) {
        if (serviceProvider.getClaimConfig() == null) {
            return new ClaimMapping[0];
        }
        return serviceProvider.getClaimConfig().getClaimMappings();
    }

    private Map<String, Object> getUserClaimsInOIDCDialect(String spTenantDomain,
                                                           Map<String, String> userClaims)
            throws ClaimMetadataException {
        // Retrieve OIDC to Local Claim Mappings.
        Map<String, String> oidcToLocalClaimMappings = ClaimMetadataHandler.getInstance()
                .getMappingsMapFromOtherDialectToCarbon(OIDC_DIALECT, null, spTenantDomain, false);
        // Get user claims in OIDC dialect.
        return getUserClaimsInOidcDialect(oidcToLocalClaimMappings, userClaims);
    }

    private Map<String, String> getUserClaimsInLocalDialect(String username,
                                                            UserRealm realm,
                                                            List<String> claimURIList)
            throws UserStoreException {
        return realm.getUserStoreManager()
                .getUserClaimValues(
                        MultitenantUtils.getTenantAwareUsername(username),
                        claimURIList.toArray(new String[claimURIList.size()]),
                        null);
    }

    private void handleServiceProviderRoleMappings(ServiceProvider serviceProvider,
                                                   String claimSeparator,
                                                   Map<String, String> userClaims) throws FrameworkException {
        for (String roleGroupClaimURI : IdentityUtil.getRoleGroupClaims()) {
            handleSPRoleMapping(serviceProvider, claimSeparator, userClaims, roleGroupClaimURI);
        }
    }

    private void handleSPRoleMapping(ServiceProvider serviceProvider, String claimSeparator, Map<String, String>
            userClaims, String roleGroupClaimURI) throws FrameworkException {

        if (isNotEmpty(userClaims) && userClaims.containsKey(roleGroupClaimURI)) {
            String roleClaim = userClaims.get(roleGroupClaimURI);
            List<String> rolesList = Arrays.asList(roleClaim.split(Pattern.quote(claimSeparator)));
            String spMappedRoleClaim =
                    OIDCClaimUtil.getServiceProviderMappedUserRoles(serviceProvider, rolesList, claimSeparator);
            userClaims.put(roleGroupClaimURI, spMappedRoleClaim);
        }
    }

    private String getServiceProviderTenantDomain(OAuthTokenReqMessageContext requestMsgCtx) {
        String spTenantDomain = (String) requestMsgCtx.getProperty(MultitenantConstants.TENANT_DOMAIN);
        // There are certain flows where tenant domain is not added as a message context property.
        if (spTenantDomain == null) {
            spTenantDomain = requestMsgCtx.getOauth2AccessTokenReqDTO().getTenantDomain();
        }
        return spTenantDomain;
    }

    private String getServiceProviderTenantDomain(OAuthAuthzReqMessageContext requestMsgCtx) {
        String spTenantDomain = (String) requestMsgCtx.getProperty(MultitenantConstants.TENANT_DOMAIN);
        // There are certain flows where tenant domain is not added as a message context property.
        if (spTenantDomain == null) {
            spTenantDomain = requestMsgCtx.getAuthorizationReqDTO().getTenantDomain();
        }
        return spTenantDomain;
    }

    private List<String> getRequestedClaimUris(ClaimMapping[] requestedLocalClaimMap) {
        List<String> claimURIList = new ArrayList<>();
        for (ClaimMapping mapping : requestedLocalClaimMap) {
            if (mapping.isRequested()) {
                claimURIList.add(mapping.getLocalClaim().getClaimUri());
            }
        }
        return claimURIList;
    }

    private ServiceProvider getServiceProvider(String spTenantDomain,
                                               String clientId) throws IdentityApplicationManagementException {
        ApplicationManagementService applicationMgtService = OAuth2ServiceComponentHolder.getApplicationMgtService();
        String spName = applicationMgtService.getServiceProviderNameByClientId(clientId, OAUTH2, spTenantDomain);

        if (log.isDebugEnabled()) {
            log.debug("Retrieving service provider for clientId: " + clientId + " in tenantDomain: " + spTenantDomain);
        }
        return applicationMgtService.getApplicationExcludingFileBasedSPs(spName, spTenantDomain);
    }

    /**
     * Get user claims in OIDC claim dialect.
     *
     * @param oidcToLocalClaimMappings OIDC dialect to Local dialect claim mappings
     * @param userClaims               User claims in local dialect
     * @return Map of user claim values in OIDC dialect.
     */
    private Map<String, Object> getUserClaimsInOidcDialect(Map<String, String> oidcToLocalClaimMappings,
                                                           Map<String, String> userClaims) {

        Map<String, Object> userClaimsInOidcDialect = new HashMap<>();
        if (isNotEmpty(userClaims)) {
            // Map<"email", "http://wso2.org/claims/emailaddress">
            for (Map.Entry<String, String> claimMapping : oidcToLocalClaimMappings.entrySet()) {
                String claimValue = userClaims.get(claimMapping.getValue());
                if (claimValue != null) {
                    String oidcClaimUri = claimMapping.getKey();
                    userClaimsInOidcDialect.put(oidcClaimUri, claimValue);
                    if (log.isDebugEnabled() &&
                            IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.USER_CLAIMS)) {
                        log.debug("Mapped claim: key - " + oidcClaimUri + " value - " + claimValue);
                    }
                }
            }
        }

        return userClaimsInOidcDialect;
    }

    /**
     * To check whether a token has custom user claims.
     *
     * @param refreshTokenValidationDataDO RefreshTokenValidationDataDO.
     * @return true if the token user attributes has non OIDC claims.
     */
    private boolean isTokenHasCustomUserClaims(RefreshTokenValidationDataDO refreshTokenValidationDataDO) {

        AuthorizationGrantCacheKey cacheKey = new AuthorizationGrantCacheKey(
                refreshTokenValidationDataDO.getAccessToken());
        AuthorizationGrantCacheEntry cacheEntry = AuthorizationGrantCache.getInstance()
                .getValueFromCacheByToken(cacheKey);
        boolean hasNonOIDCClaims = cacheEntry != null && cacheEntry.isHasNonOIDCClaims();

        if (log.isDebugEnabled()) {
            log.debug("hasNonOIDCClaims is set to " + hasNonOIDCClaims + " for the access token of the user : "
                    + refreshTokenValidationDataDO.getAuthorizedUser());
        }
        return cacheEntry != null && cacheEntry.isHasNonOIDCClaims();
    }

    /**
     * Get user attribute cached against the access token.
     *
     * @param accessToken Access token
     * @return User attributes cached against the access token
     */
    private Map<ClaimMapping, String> getUserAttributesFromCacheUsingToken(String accessToken) {
        if (log.isDebugEnabled()) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                log.debug("Retrieving user attributes cached against access token: " + accessToken);
            } else {
                log.debug("Retrieving user attributes cached against access token.");
            }
        }

        AuthorizationGrantCacheKey cacheKey = new AuthorizationGrantCacheKey(accessToken);
        AuthorizationGrantCacheEntry cacheEntry = AuthorizationGrantCache.getInstance()
                .getValueFromCacheByToken(cacheKey);

        return cacheEntry == null ? new HashMap<>() : cacheEntry.getUserAttributes();
    }

    /**
     * Get user attributes cached against the authorization code.
     *
     * @param authorizationCode Authorization Code
     * @return User attributes cached against the authorization code
     */
    private Map<ClaimMapping, String> getUserAttributesFromCacheUsingCode(String authorizationCode) {
        if (log.isDebugEnabled()) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.AUTHORIZATION_CODE)) {
                log.debug("Retrieving user attributes cached against authorization code: " + authorizationCode);
            } else {
                log.debug("Retrieving user attributes cached against authorization code.");
            }
        }

        AuthorizationGrantCacheKey cacheKey = new AuthorizationGrantCacheKey(authorizationCode);
        AuthorizationGrantCacheEntry cacheEntry =
                AuthorizationGrantCache.getInstance().getValueFromCacheByCode(cacheKey);
        return cacheEntry == null ? new HashMap<>() : cacheEntry.getUserAttributes();
    }

    /**
     * Set user claims in OIDC dialect to the JWTClaimSet. Additionally we process multi values attributes here.
     *
     * @param jwtClaimsSetBuilder
     * @param userClaimsInOIDCDialect
     */
    private JWTClaimsSet setClaimsToJwtClaimSet(JWTClaimsSet.Builder jwtClaimsSetBuilder, Map<String, Object>
            userClaimsInOIDCDialect) {

        JWTClaimsSet jwtClaimsSet = jwtClaimsSetBuilder.build();
        for (Map.Entry<String, Object> claimEntry : userClaimsInOIDCDialect.entrySet()) {
            String claimValue = claimEntry.getValue().toString();
            String claimKey = claimEntry.getKey();
            if (isMultiValuedAttribute(claimKey, claimValue)) {
                JSONArray claimValues = new JSONArray();
                String[] attributeValues = claimValue.split(Pattern.quote(ATTRIBUTE_SEPARATOR));
                for (String attributeValue : attributeValues) {
                    if (StringUtils.isNotBlank(attributeValue)) {
                        claimValues.add(attributeValue);
                    }
                }
                if (jwtClaimsSet.getClaim(claimKey) == null) {
                    jwtClaimsSetBuilder.claim(claimEntry.getKey(), claimValues);
                }
            } else {
                if (jwtClaimsSet.getClaim(claimKey) == null) {
                    jwtClaimsSetBuilder.claim(claimEntry.getKey(), claimEntry.getValue());
                }
            }
        }
        return jwtClaimsSetBuilder.build();
    }

    private String getAuthorizationCode(OAuthTokenReqMessageContext requestMsgCtx) {
        return (String) requestMsgCtx.getProperty(AUTHZ_CODE);
    }

    private String getDeviceCode(OAuthTokenReqMessageContext requestMsgCtx) {

        return (String) requestMsgCtx.getProperty(DEVICE_CODE);
    }

    private String getAccessToken(OAuthTokenReqMessageContext requestMsgCtx) {
        return (String) requestMsgCtx.getProperty(ACCESS_TOKEN);
    }

    private String getAccessToken(OAuthAuthzReqMessageContext authzReqMessageContext) {
        return (String) authzReqMessageContext.getProperty(ACCESS_TOKEN);
    }

    private boolean isLocalUser(AuthenticatedUser authenticatedUser) {
        return !authenticatedUser.isFederatedUser();
    }

    private boolean isLocalUser(OAuthAuthzReqMessageContext authzReqMessageContext) {
        return !authzReqMessageContext.getAuthorizationReqDTO().getUser().isFederatedUser();
    }

    private boolean isMultiValuedAttribute(String claimKey, String claimValue) {

        // Address claim contains multi attribute separator but its not a multi valued attribute.
        if (claimKey.equals(ADDRESS)) {
            return false;
        }
        // To format the groups claim to always return as an array, we should consider single group as
        // multi value attribute.
        if (claimKey.equals(GROUPS)) {
            return true;
        }
        return StringUtils.contains(claimValue, ATTRIBUTE_SEPARATOR);
    }

    /**
     * The access token hash acts as the key for entries in the SessionStore.
     * This method retrieves the access token hash for OAuthConstants.ACCESS_TOKEN from the properties
     * of OAuthTokenReqMessageContext treating it as the latest access token. It determines the type
     * of access token (opaque or JWT) via the OAuth token issuer and obtains the access token hash accordingly.
     * This method is useful for retrieving access tokens when the cache is disabled and
     * SessionStore persistence is employed.
     *
     * @param oAuthTokenReqMessageContext The context of the OAuth token request containing necessary properties.
     * @return The hash of the latest access token if available and valid, otherwise null.
     * @throws IdentityOAuth2Exception If an error occurs while selecting the OAuth2 token issuer.
     * @throws OAuthSystemException    If there is an error while generating the access token hash.
     */
    private String getLatestAccessTokenHash(OAuthTokenReqMessageContext oAuthTokenReqMessageContext)
            throws IdentityOAuth2Exception, OAuthSystemException {

        // The OAuthConstants.ACCESS_TOKEN is considered as the latest access token.
        Object latestAccessTokenObj = getAccessToken(oAuthTokenReqMessageContext);
        if (latestAccessTokenObj != null && StringUtils.isNotBlank(latestAccessTokenObj.toString())) {

            Object oAuthAppDOObj = oAuthTokenReqMessageContext.getProperty(AccessTokenIssuer.OAUTH_APP_DO);

            if (oAuthAppDOObj != null) {
                try {
                    OAuthAppDO oAuthAppDO = (OAuthAppDO) oAuthAppDOObj;
                    OauthTokenIssuer tokenIssuer = OAuth2Util.getOAuthTokenIssuerForOAuthApp(oAuthAppDO);
                    if (tokenIssuer != null) {
                        String latestAccessToken = latestAccessTokenObj.toString();
                        return tokenIssuer.getAccessTokenHash(latestAccessToken);
                    }
                } catch (ClassCastException e) {
                    log.error("Error occurred while generating the access token hash at user attribute " +
                            "retrieval", e);

                }
            }
        }
        return null;
    }
}
