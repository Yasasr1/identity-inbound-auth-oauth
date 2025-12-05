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

package org.wso2.carbon.identity.oauth2.util;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * Utility class for JWT related operations.
 */
public class JWTUtils {

    private static final Log LOG = LogFactory.getLog(JWTUtils.class);
    private static final String DOT_SEPARATOR = ".";
    private static final String OIDC_IDP_ENTITY_ID = "IdPEntityId";
    private static final String ALGO_PREFIX = "RS";
    private static final String ALGO_PREFIX_PS = "PS";

    /**
     * Return true if the token identifier is JWT.
     *
     * @param tokenIdentifier String JWT token identifier.
     * @return true for a JWT token.
     */
    public static boolean isJWT(String tokenIdentifier) {

        // JWT token contains 3 base64 encoded components separated by periods.
        return StringUtils.countMatches(tokenIdentifier, DOT_SEPARATOR) == 2;
    }

    /**
     * Retrieves the resident Identity Provider (IDP) associated with the issuer of the provided JSON Web Token (JWT)
     * claims set within the context of a given tenant.
     *
     * @param claimsSet    The JWTClaimsSet containing the claims of the JWT, including the issuer
     * @param tenantDomain The domain of the tenant for which the resident IDP needs to be retrieved.
     * @return The resident Identity Provider associated with the JWT issuer
     * @throws IdentityOAuth2Exception If an error occurs while processing OAuth2-related functionality.
     */
    public static IdentityProvider getResidentIDPForIssuer(JWTClaimsSet claimsSet, String tenantDomain)
            throws IdentityOAuth2Exception {

        String issuer = StringUtils.EMPTY;
        IdentityProvider residentIdentityProvider;
        try {
            residentIdentityProvider = IdentityProviderManager.getInstance().getResidentIdP(tenantDomain);
        } catch (IdentityProviderManagementException e) {
            String errorMsg =
                    String.format("Error while getting Resident Identity Provider of '%s' tenant.", tenantDomain);
            throw new IdentityOAuth2Exception(errorMsg, e);
        }
        FederatedAuthenticatorConfig[] fedAuthnConfigs = residentIdentityProvider.getFederatedAuthenticatorConfigs();
        FederatedAuthenticatorConfig oauthAuthenticatorConfig =
                IdentityApplicationManagementUtil.getFederatedAuthenticator(fedAuthnConfigs,
                        IdentityApplicationConstants.Authenticator.OIDC.NAME);
        if (oauthAuthenticatorConfig != null) {
            issuer = IdentityApplicationManagementUtil.getProperty(oauthAuthenticatorConfig.getProperties(),
                    OIDC_IDP_ENTITY_ID).getValue();
        }
        if (!claimsSet.getIssuer().equals(issuer)) {
            throw new IdentityOAuth2Exception("No Registered IDP found for the token with issuer name : "
                    + claimsSet.getIssuer());
        }
        return residentIdentityProvider;
    }

    /**
     * Checks if the provided expiration time of a token is valid, considering the configured timestamp skew.
     *
     * @param expirationTime The expiration time of the token to be checked.
     * @return True if the token is not expired, false otherwise.
     */
    public static boolean checkExpirationTime(Date expirationTime) {

        long timeStampSkewMillis = OAuthServerConfiguration.getInstance().getTimeStampSkewInSeconds() * 1000;
        long expirationTimeInMillis = expirationTime.getTime();
        long currentTimeInMillis = System.currentTimeMillis();
        if ((currentTimeInMillis + timeStampSkewMillis) > expirationTimeInMillis) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Token is expired." +
                        ", Expiration Time(ms) : " + expirationTimeInMillis +
                        ", TimeStamp Skew : " + timeStampSkewMillis +
                        ", Current Time : " + currentTimeInMillis + ". Token Rejected and validation terminated.");
            }
            return false;
        }

        LOG.debug("Expiration Time(exp) of Token was validated successfully.");
        return true;
    }

    /**
     * Validates that the provided token's "Not Before" time has passed, considering the configured timestamp skew.
     * If the token is used before the "Not Before" time, an IdentityOAuth2Exception is thrown.
     *
     * @param notBeforeTime The "Not Before" time of the token to be validated.
     * @throws IdentityOAuth2Exception If the token is used before the "Not Before" time.
     */
    public static void checkNotBeforeTime(Date notBeforeTime) throws IdentityOAuth2Exception {

        if (notBeforeTime != null) {
            long timeStampSkewMillis = OAuthServerConfiguration.getInstance().getTimeStampSkewInSeconds() * 1000;
            long notBeforeTimeMillis = notBeforeTime.getTime();
            long currentTimeInMillis = System.currentTimeMillis();
            if (currentTimeInMillis + timeStampSkewMillis < notBeforeTimeMillis) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Token is used before Not_Before_Time." +
                            ", Not Before Time(ms) : " + notBeforeTimeMillis +
                            ", TimeStamp Skew : " + timeStampSkewMillis +
                            ", Current Time : " + currentTimeInMillis + ". Token Rejected and validation terminated.");
                }
                if (LoggerUtils.isDiagnosticLogsEnabled()) {
                    Map<String, Object> params = new HashMap<>();
                    params.put("notBeforeTime", notBeforeTimeMillis);
                    params.put("timestampSkew", timeStampSkewMillis);
                    params.put("currentTime", currentTimeInMillis);
                    LoggerUtils.triggerDiagnosticLogEvent(OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE, params,
                            OAuthConstants.LogConstants.FAILED, "Token is used before Not_Before_Time.",
                            "validate-jwt-access-token", null);
                }
                throw new IdentityOAuth2Exception("Token is used before Not_Before_Time.");
            }
            if (LOG.isDebugEnabled()) {
                LOG.debug("Not Before Time(nbf) of Token was validated successfully.");
            }
        }
    }

    /**
     * Verifies and retrieves the signature algorithm from the header of the given SignedJWT.
     *
     * @param signedJWT The SignedJWT from which to verify and retrieve the signature algorithm.
     * @return The signature algorithm.
     * @throws IdentityOAuth2Exception If the algorithm is null or empty in the token header.
     */
    public static String verifyAlgorithm(SignedJWT signedJWT) throws IdentityOAuth2Exception {

        String alg = signedJWT.getHeader().getAlgorithm().getName();
        if (StringUtils.isEmpty(alg)) {
            throw new IdentityOAuth2Exception("Algorithm must not be null.");
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("Signature Algorithm found in the Token Header: " + alg);
        }
        return alg;
    }

    /**
     * Verifies the signature of the given SignedJWT using the provided X.509 certificate and signature algorithm.
     *
     * @param signedJWT       The SignedJWT to verify.
     * @param x509Certificate The X.509 certificate used for signature verification.
     * @param alg             The signature algorithm.
     * @return True if the signature is valid, false otherwise.
     * @throws IdentityOAuth2Exception If an error occurs during signature verification.
     * @throws JOSEException           If an error occurs in the JOSE library.
     */
    public static boolean verifySignature(SignedJWT signedJWT, X509Certificate x509Certificate, String alg)
            throws IdentityOAuth2Exception, JOSEException {

        JWSVerifier verifier = null;
        if (alg.indexOf(ALGO_PREFIX) == 0 || alg.indexOf(ALGO_PREFIX_PS) == 0) {
            // At this point 'x509Certificate' will never be null.
            PublicKey publicKey = x509Certificate.getPublicKey();
            if (publicKey instanceof RSAPublicKey) {
                verifier = new RSASSAVerifier((RSAPublicKey) publicKey);
            } else {
                throw new IdentityOAuth2Exception("Public key is not an RSA public key.");
            }
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Signature Algorithm not supported yet: " + alg);
            }
        }
        if (verifier == null) {
            throw new IdentityOAuth2Exception("Could not create a signature verifier for algorithm type: " + alg);
        }
        boolean isValid;
        isValid = signedJWT.verify(verifier);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Signature verified: " + isValid);
        }
        return isValid;
    }
}
