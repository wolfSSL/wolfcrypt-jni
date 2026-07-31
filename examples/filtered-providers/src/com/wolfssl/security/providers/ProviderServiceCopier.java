/* ProviderServiceCopier.java
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */
package com.wolfssl.security.providers;

import java.lang.reflect.Field;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

/**
 * Shared helper for the FilteredSun, FilteredSunEC, and FilteredSunRsaSign
 * providers. Builds a copy of a Provider.Service from one of the original Sun
 * providers, using reflection to read the private className/aliases/attributes
 * fields of java.security.Provider.Service (and the private "string" field of
 * the attribute-key class).
 *
 * Provider.putService() is protected, so this helper (which is not itself a
 * Provider subclass) cannot call target.putService() directly. Instead it
 * RETURNS the constructed Provider.Service and the caller, which is a Provider
 * subclass, invokes this.putService(...) on the returned instance.
 *
 * Requires Java 9+. The reflective access requires the JVM module flags
 * documented in docs/add-opens.md.
 */
final class ProviderServiceCopier {

    private ProviderServiceCopier() {
    }

    /** Security property enabling original Sun provider names. */
    private static final String USE_ORIGINAL_NAMES_PROP =
        "wolfssl.filtered.useOriginalNames";

    /** Name of the per-provider additionalServices Security property. */
    private static String additionalServicesPropName(String providerKey) {
        return "wolfssl.filtered." + providerKey + ".additionalServices";
    }

    /**
     * Resolve the name a filtered provider should register under.
     *
     * By default the filtered name is returned. When the
     * wolfssl.filtered.useOriginalNames Security property is set to "true"
     * (in java.security, or via Security.setProperty() before the providers
     * are first instantiated), the original Sun provider name is returned
     * instead, so that applications and JDK code with hardcoded provider
     * names keep working.
     *
     * NOTE: with this property enabled, the providers must be registered by
     * class name in java.security. A provider-name entry
     * (ex: security.provider.N=SUN) resolves to the stock Sun provider through
     * the JDK built-in name resolution, silently bypassing the filtered
     * provider.
     *
     * @param filteredName default name, e.g. "FilteredSun"
     * @param originalName original Sun provider name, e.g. "SUN"
     *
     * @return the name to pass to the Provider super constructor
     */
    static String resolveName(String filteredName, String originalName) {

        String prop = Security.getProperty(USE_ORIGINAL_NAMES_PROP);

        if (prop != null) {
            String val = prop.trim();

            if ("true".equalsIgnoreCase(val)) {
                return originalName;
            }

            /* Warn on values other than "true"/"false"/"", such as a
             * java.security inline comment mistake like: "true # comment" */
            if (!val.isEmpty() && !"false".equalsIgnoreCase(val)) {
                System.err.println(filteredName + ": unrecognized value '" +
                    val + "' for Security property " +
                    USE_ORIGINAL_NAMES_PROP + ", treating as false");
            }
        }

        return filteredName;
    }

    /**
     * Split a trimmed Type.Algorithm entry on its first '.' only, since
     * algorithm names may themselves contain dots
     * (ex: CertStore.com.sun.security.IndexedCollection).
     *
     * @param entry trimmed Type.Algorithm entry
     *
     * @return array of type and algorithm, or null if malformed (no dot,
     *         empty type, or empty algorithm)
     */
    private static String[] parseEntry(String entry) {

        int dot;
        String type, algo;

        dot = entry.indexOf('.');
        if (dot <= 0 || dot == entry.length() - 1) {
            return null;
        }

        type = entry.substring(0, dot).trim();
        algo = entry.substring(dot + 1).trim();

        if (type.isEmpty() || algo.isEmpty()) {
            return null;
        }

        return new String[] { type, algo };
    }

    /** Lowercase "type.algorithm" key used for grant matching. */
    private static String serviceKey(String type, String algo) {
        return (type + "." + algo).toLowerCase(Locale.ROOT);
    }

    /**
     * Read the per-provider additionalServices Security property. Read once
     * per construction and passed to both additionalServiceKeys() and
     * warnIgnoredEntries(), so the grant and warning passes see the same
     * value.
     *
     * @param providerKey lowercase key: "sun", "sunec", or "sunrsasign"
     *
     * @return property value, or null if unset
     */
    static String additionalServicesProperty(String providerKey) {
        return Security.getProperty(additionalServicesPropName(providerKey));
    }

    /**
     * Parse an additionalServices property value into grant keys for
     * serviceAllowedByProperty(). The value is a comma-separated list of
     * Type.Algorithm entries, for example:
     *
     *     wolfssl.filtered.sun.additionalServices=MessageDigest.MD5
     *
     * Entries match case-insensitively against canonical service names.
     * Aliases cannot specify a grant, though a granted copy keeps its
     * aliases. Malformed entries are ignored here and reported by
     * warnIgnoredEntries(). Security property only, a System property of
     * the same name would have no effect.
     *
     * @param prop property value from additionalServicesProperty()
     *
     * @return grant keys, empty if the property is unset or empty
     */
    static Set<String> additionalServiceKeys(String prop) {

        Set<String> keys = new HashSet<>();

        if (prop == null || prop.trim().isEmpty()) {
            return keys;
        }

        for (String entry : prop.split(",")) {
            String[] parts = parseEntry(entry.trim());
            if (parts != null) {
                keys.add(serviceKey(parts[0], parts[1]));
            }
        }

        return keys;
    }

    /**
     * Check if grantKeys (from additionalServiceKeys()) grants a service.
     *
     * @param grantKeys parsed grant keys
     * @param service candidate service from the original Sun provider
     *
     * @return true if granted
     */
    static boolean serviceAllowedByProperty(Set<String> grantKeys,
        Provider.Service service) {

        return grantKeys.contains(
            serviceKey(service.getType(), service.getAlgorithm()));
    }

    /**
     * Warn to System.err for each additionalServices entry that will
     * never grant a service: malformed entries and entries matching no
     * original provider service. Called after each constructor's copy
     * loop so misconfigured grants show at startup. Empty entries are
     * skipped.
     *
     * @param providerKey lowercase key: "sun", "sunec", or "sunrsasign"
     * @param providerName fixed filtered name to prefix warnings with
     *        (not getName(), which may be the original Sun name)
     * @param prop property value from additionalServicesProperty(), the
     *        same value the grant pass parsed
     * @param original the original Sun provider
     */
    static void warnIgnoredEntries(String providerKey, String providerName,
        String prop, Provider original) {

        String propName = additionalServicesPropName(providerKey);

        if (prop == null || prop.trim().isEmpty()) {
            return;
        }

        /* Canonical keys only, matching the grant pass. Must not use
         * original.getService(), it resolves aliases and would report an
         * alias/OID entry as matched when the grant pass never matches
         * it. */
        Set<String> originalKeys = new HashSet<>();
        for (Provider.Service s : original.getServices()) {
            originalKeys.add(serviceKey(s.getType(), s.getAlgorithm()));
        }

        for (String rawEntry : prop.split(",")) {
            String entry = rawEntry.trim();
            if (entry.isEmpty()) {
                continue;
            }

            String[] parts = parseEntry(entry);
            if (parts == null) {
                System.err.println(providerName +
                    ": ignored malformed entry '" + entry + "' in " +
                    propName + " (expected Type.Algorithm)");
                continue;
            }

            if (!originalKeys.contains(serviceKey(parts[0], parts[1]))) {
                System.err.println(providerName + ": entry '" + entry +
                    "' in " + propName + " matches no " +
                    original.getName() + " service, entry ignored (use " +
                    "canonical Type.Algorithm names, aliases and OIDs do " +
                    "not match)");
            }
        }
    }

    /**
     * Warn to System.err when a system property matching one of the Security
     * properties this provider reads is set. System properties are ignored.
     * This catches -Dwolfssl.filtered...=... configs (ex: via
     * JAVA_TOOL_OPTIONS, which can only set system properties).
     *
     * @param providerKey lowercase key: "sun", "sunec", or "sunrsasign"
     * @param providerName filtered provider name to prefix warnings with
     */
    static void warnIgnoredSystemProperties(String providerKey,
        String providerName) {

        String[] propNames = {
            USE_ORIGINAL_NAMES_PROP,
            additionalServicesPropName(providerKey) };

        for (String propName : propNames) {
            if (System.getProperty(propName) != null) {
                System.err.println(providerName + ": system property " +
                    propName + " is ignored, set it as a Security " +
                    "property in java.security or with " +
                    "Security.setProperty() before provider construction");
            }
        }
    }

    /**
     * Build a copy of originalService owned by target.
     *
     * @param target provider that will own the returned service; the caller
     *        must invoke putService() on the returned value
     * @param originalService service to copy from the original Sun provider
     * @param delegateNewInstance if true, the returned service overrides
     *        newInstance() to delegate to originalService (required when the
     *        copied service must instantiate via the original provider's
     *        implementation, e.g. SunEC AlgorithmParameters or SunRsaSign
     *        KeyFactory); if false, a plain copied Provider.Service is returned
     *
     * @return a new Provider.Service owned by target
     */
    static Provider.Service buildService(Provider target,
        final Provider.Service originalService, boolean delegateNewInstance) {

        try {
            /* Get class name */
            Field classNameField =
                Provider.Service.class.getDeclaredField("className");
            classNameField.setAccessible(true);
            String className = (String) classNameField.get(originalService);

            /* Get aliases */
            Field aliasesField =
                Provider.Service.class.getDeclaredField("aliases");
            aliasesField.setAccessible(true);

            @SuppressWarnings("unchecked")
            List<String> aliases =
                (List<String>) aliasesField.get(originalService);

            /* Get attributes, build new attributes map */
            Field attributesField =
                Provider.Service.class.getDeclaredField("attributes");
            attributesField.setAccessible(true);

            @SuppressWarnings("unchecked")
            Map<?, ?> rawAttributes =
                (Map<?, ?>) attributesField.get(originalService);
            Map<String, String> attributes = new HashMap<>();
            if (rawAttributes != null) {
                for (Entry<?, ?> entry : rawAttributes.entrySet()) {
                    Object key = entry.getKey();
                    Field stringField =
                        key.getClass().getDeclaredField("string");
                    stringField.setAccessible(true);
                    String originalKey = (String) stringField.get(key);
                    attributes.put(originalKey, (String) entry.getValue());
                }
            }

            List<String> aliasCopy =
                (aliases != null) ? new ArrayList<>(aliases) : null;

            if (!delegateNewInstance) {
                return new Provider.Service(target,
                    originalService.getType(), originalService.getAlgorithm(),
                    className, aliasCopy, attributes);
            }

            /* Delegate instantiation to the original service. */
            return new Provider.Service(target,
                originalService.getType(), originalService.getAlgorithm(),
                className, aliasCopy, attributes) {

                @Override
                public Object newInstance(Object constructorParameter)
                    throws NoSuchAlgorithmException {
                    return originalService.newInstance(constructorParameter);
                }
            };

        } catch (NoSuchFieldException | IllegalAccessException e) {
            throw new RuntimeException("Failed to copy service: " +
                originalService.getType() + "/" +
                originalService.getAlgorithm(), e);
        }
    }
}

