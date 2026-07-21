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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

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

