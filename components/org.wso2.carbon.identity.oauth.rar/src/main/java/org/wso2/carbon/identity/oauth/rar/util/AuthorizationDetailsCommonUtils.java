/*
 * Copyright (c) 2025, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.oauth.rar.util;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.rar.model.AuthorizationDetail;
import org.wso2.carbon.identity.oauth.rar.model.AuthorizationDetails;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import static org.wso2.carbon.identity.oauth.rar.util.AuthorizationDetailsConstants.EMPTY_JSON_ARRAY;
import static org.wso2.carbon.identity.oauth.rar.util.AuthorizationDetailsConstants.EMPTY_JSON_OBJECT;

/**
 * Utility class for handling OAuth2 Rich Authorization Requests.
 */
public class AuthorizationDetailsCommonUtils {

    private static final Log log = LogFactory.getLog(AuthorizationDetailsCommonUtils.class);

    private static volatile ObjectMapper objectMapper;
    private static final TypeReference<Map<String, Object>> TYPE_MAP = new TypeReference<Map<String, Object>>() { };

    private static final String FIELD_SEPARATOR = ", ";
    private static final String FIELD_VALUE_SEPARATOR = ": ";
    private static final String LIST_VALUE_SEPARATOR = ", ";
    // The type heads a generated consent description, and '_id'/'_description' are ours rather than the client's.
    private static final List<String> INTERNAL_AUTHORIZATION_DETAIL_FIELDS =
            Collections.unmodifiableList(Arrays.asList("type", "_id", "_description"));
    // RFC 9396 common data fields, rendered ahead of the API specific ones and in the order the RFC lists them.
    private static final List<String> COMMON_DATA_FIELDS = Collections.unmodifiableList(
            Arrays.asList("locations", "actions", "datatypes", "identifier", "privileges"));

    private AuthorizationDetailsCommonUtils() {
        // Private constructor to prevent instantiation
    }

    /**
     * Parses the given JSON array string into a set of {@link AuthorizationDetail} objects.
     *
     * @param authorizationDetailsJson A JSON string containing authorization details which comes in the
     *                                 OAuth 2.0 authorization request or token request
     * @param clazz                    A Class that extends {@link AuthorizationDetail} to be parsed
     * @param <T>                      the type parameter extending {@code AuthorizationDetail}
     * @return an immutable set of {@link AuthorizationDetail} objects parsed from the given JSON string,
     * or an empty set if parsing fails
     * @see AuthorizationDetails
     */
    public static <T extends AuthorizationDetail> Set<T> fromJSONArray(final String authorizationDetailsJson,
                                                                       final Class<T> clazz) {

        try {
            if (StringUtils.isNotEmpty(authorizationDetailsJson)) {
                return getDefaultObjectMapper().readValue(authorizationDetailsJson,
                        getDefaultObjectMapper().getTypeFactory().constructCollectionType(Set.class, clazz));
            }
        } catch (JsonProcessingException e) {
            log.debug("Error occurred while parsing String to AuthorizationDetails. Caused by, ", e);
        }
        return new HashSet<>();
    }

    /**
     * Parses the given JSON object string into an {@link AuthorizationDetail} object.
     *
     * @param authorizationDetailJson A JSON string containing authorization detail object
     * @param clazz                   A Class that extends {@link AuthorizationDetail} to be parsed
     * @param <T>                     the type parameter extending {@code AuthorizationDetail}
     * @return an {@link AuthorizationDetail} objects parsed from the given JSON string,
     * or null if parsing fails
     * @see AuthorizationDetail
     */
    public static <T extends AuthorizationDetail> T fromJSON(final String authorizationDetailJson,
                                                             final Class<T> clazz) {

        try {
            if (StringUtils.isNotEmpty(authorizationDetailJson)) {
                return getDefaultObjectMapper().readValue(authorizationDetailJson, clazz);
            }
        } catch (JsonProcessingException e) {
            log.debug("Error occurred while parsing String to AuthorizationDetails. Caused by, ", e);
        }
        return null;
    }

    /**
     * Builds a consent description for an authorization detail out of the values the client actually sent, for use
     * when no {@link org.wso2.carbon.identity.oauth.rar.core.AuthorizationDetailsSchemaValidator} aware processor is
     * registered for its type to author a better one.
     * <p>
     * The result reads as {@code type (field: value, field: value)} with the RFC 9396 common data fields first and the
     * API specific fields after them, both in a stable order. Nested values are rendered as compact JSON. A detail
     * carrying nothing but a {@code type} yields just the type, which is what the consent page displayed before.
     * </p>
     *
     * @param authorizationDetail The authorization detail to describe.
     * @return A human readable description of the authorization detail, or {@code null} if there is nothing to
     * describe.
     * @see AuthorizationDetail#getDescriptionOrDefault(java.util.function.Function)
     */
    public static String buildDefaultConsentDescription(final AuthorizationDetail authorizationDetail) {

        if (authorizationDetail == null || StringUtils.isBlank(authorizationDetail.getType())) {
            return null;
        }

        final Map<String, Object> allFields = toMap(authorizationDetail);
        /*
         * Order the fields explicitly: the same request has to produce the same description every time, since it is
         * what the user reads and what is persisted with their consent. The field map is not ordered on its own.
         */
        final Map<String, Object> fields = new LinkedHashMap<>();
        COMMON_DATA_FIELDS.stream().filter(allFields::containsKey)
                .forEach(field -> fields.put(field, allFields.get(field)));
        allFields.keySet().stream()
                .filter(field -> !COMMON_DATA_FIELDS.contains(field))
                // The type heads the description, and the internal fields are not the client's to display.
                .filter(field -> !INTERNAL_AUTHORIZATION_DETAIL_FIELDS.contains(field))
                .sorted()
                .forEach(field -> fields.put(field, allFields.get(field)));

        final String renderedFields = fields.entrySet().stream()
                .filter(field -> field.getValue() != null)
                .map(field -> field.getKey() + FIELD_VALUE_SEPARATOR + renderFieldValue(field.getValue()))
                .collect(Collectors.joining(FIELD_SEPARATOR));

        return StringUtils.isBlank(renderedFields) ? authorizationDetail.getType()
                : authorizationDetail.getType() + " (" + renderedFields + ")";
    }

    /**
     * Renders a single authorization detail field value. Scalars are rendered as they were sent; lists are comma
     * separated; anything structured falls back to compact JSON so no requested value is hidden from the user.
     *
     * @param value The field value.
     * @return The rendered value.
     */
    private static String renderFieldValue(final Object value) {

        if (value instanceof Collection) {
            return ((Collection<?>) value).stream()
                    .filter(Objects::nonNull)
                    .map(AuthorizationDetailsCommonUtils::renderFieldValue)
                    .collect(Collectors.joining(LIST_VALUE_SEPARATOR));
        }
        if (value instanceof Map) {
            try {
                return getDefaultObjectMapper().writeValueAsString(value);
            } catch (JsonProcessingException e) {
                log.debug("Unable to render an authorization detail field value as JSON. Caused by, ", e);
                return String.valueOf(value);
            }
        }
        return String.valueOf(value);
    }

    /**
     * Converts a set of {@code AuthorizationDetail} objects into a JSON string.
     * <p>
     * If the input set is {@code null} or an exception occurs during the conversion,
     * an empty JSON array ({@code []}) is returned.
     * </p>
     *
     * @param authorizationDetails the set of {@code AuthorizationDetail} objects to convert
     * @param <T>                  the type parameter extending {@code AuthorizationDetail}
     * @return a JSON string representation of the authorization details set,
     * or an empty JSON array if null or an error occurs
     * @see AuthorizationDetail
     * @see AuthorizationDetails
     */
    public static <T extends AuthorizationDetail> String toJSON(final Set<T> authorizationDetails) {

        try {
            if (authorizationDetails != null) {
                return getDefaultObjectMapper().writeValueAsString(authorizationDetails);
            }
        } catch (JsonProcessingException e) {
            log.debug("Error occurred while parsing AuthorizationDetails to String. Caused by, ", e);
        }
        return EMPTY_JSON_ARRAY;
    }

    /**
     * Converts a single {@code AuthorizationDetail} object into a JSON string.
     * <p>
     * If the input object is {@code null} or an exception occurs during the conversion,
     * an empty JSON object ({@code {}}) is returned.
     * </p>
     *
     * @param authorizationDetail the {@code AuthorizationDetail} object to convert
     * @param <T>                 the type parameter extending {@code AuthorizationDetail}
     * @return a JSON string representation of the authorization detail,
     * or an empty JSON object if null or an error occurs
     * @see AuthorizationDetail
     * @see AuthorizationDetails
     */
    public static <T extends AuthorizationDetail> String toJSON(final T authorizationDetail) {

        try {
            if (authorizationDetail != null) {
                return getDefaultObjectMapper().writeValueAsString(authorizationDetail);
            }
        } catch (JsonProcessingException e) {
            log.debug("Error occurred while parsing AuthorizationDetail to String. Caused by, ", e);
        }
        return EMPTY_JSON_OBJECT;
    }

    /**
     * Converts a single {@code AuthorizationDetail} object into a {@link Map}.
     * <p>
     * If the input object is {@code null} or an exception occurs during the conversion,
     * an empty {@link HashMap} is returned.
     * </p>
     *
     * @param authorizationDetail the {@code AuthorizationDetail} object to convert
     * @param <T>                 the type parameter extending {@code AuthorizationDetail}
     * @return a {@code Map} representation of the authorization detail,
     * or an empty {@code HashMap} if null or an error occurs
     * @see AuthorizationDetail
     * @see AuthorizationDetails
     */
    public static <T extends AuthorizationDetail> Map<String, Object> toMap(final T authorizationDetail) {

        return (authorizationDetail == null) ? Collections.emptyMap()
                : getDefaultObjectMapper().convertValue(authorizationDetail, TYPE_MAP);
    }

    /**
     * Returns a configured default {@link ObjectMapper} instance.
     *
     * <p>This singleton ObjectMapper is configured to exclude properties with null values from the JSON output.
     *
     * @return a configured {@link ObjectMapper} instance.
     */
    public static ObjectMapper getDefaultObjectMapper() {
        if (objectMapper == null) {
            synchronized (AuthorizationDetailsCommonUtils.class) {
                if (objectMapper == null) {
                    objectMapper = new ObjectMapper();
                    objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
                }
            }
        }
        return objectMapper;
    }
}
