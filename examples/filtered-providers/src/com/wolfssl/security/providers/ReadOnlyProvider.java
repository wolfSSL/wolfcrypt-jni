/* ReadOnlyProvider.java
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

import java.io.IOException;
import java.io.InputStream;
import java.io.InvalidObjectException;
import java.io.ObjectInputStream;
import java.io.ObjectStreamException;
import java.io.Reader;
import java.security.Provider;
import java.security.Security;
import java.util.Map;
import java.util.function.BiFunction;
import java.util.function.Function;

/**
 * Base class for the filtered providers. Services can be added only until the
 * subclass constructor calls setReadOnly(). After that every Provider and
 * Properties method that changes services throws SecurityException, so other
 * code cannot add a service (for example put("MessageDigest.MD5", ...)) that
 * the filter did not allow.
 */
abstract class ReadOnlyProvider extends Provider {

    private static final long serialVersionUID = 1L;

    private transient volatile boolean readOnly = false;

    /* False for deserialized objects, which can never be changed */
    private final transient boolean constructed;

    ReadOnlyProvider(String name, String versionStr, String info) {
        super(name, versionStr, info);
        constructed = true;
    }

    /**
     * Make this provider services read-only. Called at the end of the
     * subclass constructor.
     */
    final synchronized void setReadOnly() {
        readOnly = true;
    }

    /* Make the deserialized object read-only. Replaced by readResolve(). */
    private void readObject(ObjectInputStream in)
        throws IOException, ClassNotFoundException {
        readOnly = true;
        in.defaultReadObject();
    }

    /**
     * Replace a deserialized provider with the registered provider of the
     * same name and class, or a new instance, so services always come from
     * the filter in the constructor and never from serialized data.
     *
     * @return the registered provider, or a new instance of this class
     * @throws ObjectStreamException if a new instance cannot be created
     */
    protected Object readResolve() throws ObjectStreamException {

        Provider p = Security.getProvider(getName());
        if (p != null && p.getClass() == getClass()) {
            return p;
        }

        try {
            return getClass().getDeclaredConstructor().newInstance();

        } catch (ReflectiveOperationException e) {
            InvalidObjectException ioe = new InvalidObjectException(
                "Cannot create " + getClass().getName() + ": " + e);
            ioe.initCause(e);
            throw ioe;
        }
    }

    private void checkNotReadOnly() {
        if (readOnly || !constructed) {
            throw new SecurityException(getName() +
                " provider services cannot be modified");
        }
    }

    @Override
    public synchronized Object put(Object key, Object value) {
        checkNotReadOnly();
        return super.put(key, value);
    }

    @Override
    public synchronized void putAll(Map<?, ?> t) {
        /* Drop entries restored by Provider.readObject() */
        if (!constructed && !readOnly) {
            return;
        }
        checkNotReadOnly();
        super.putAll(t);
    }

    @Override
    public synchronized Object putIfAbsent(Object key, Object value) {
        checkNotReadOnly();
        return super.putIfAbsent(key, value);
    }

    @Override
    public synchronized Object remove(Object key) {
        checkNotReadOnly();
        return super.remove(key);
    }

    @Override
    public synchronized boolean remove(Object key, Object value) {
        checkNotReadOnly();
        return super.remove(key, value);
    }

    @Override
    public synchronized boolean replace(Object key, Object oldValue,
        Object newValue) {
        checkNotReadOnly();
        return super.replace(key, oldValue, newValue);
    }

    @Override
    public synchronized Object replace(Object key, Object value) {
        checkNotReadOnly();
        return super.replace(key, value);
    }

    @Override
    public synchronized void replaceAll(BiFunction<? super Object,
        ? super Object, ? extends Object> function) {
        checkNotReadOnly();
        super.replaceAll(function);
    }

    @Override
    public synchronized Object compute(Object key, BiFunction<? super Object,
        ? super Object, ? extends Object> remappingFunction) {
        checkNotReadOnly();
        return super.compute(key, remappingFunction);
    }

    @Override
    public synchronized Object computeIfAbsent(Object key, Function<? super
        Object, ? extends Object> mappingFunction) {
        checkNotReadOnly();
        return super.computeIfAbsent(key, mappingFunction);
    }

    @Override
    public synchronized Object computeIfPresent(Object key, BiFunction<?
        super Object, ? super Object, ? extends Object> remappingFunction) {
        checkNotReadOnly();
        return super.computeIfPresent(key, remappingFunction);
    }

    @Override
    public synchronized Object merge(Object key, Object value,
        BiFunction<? super Object, ? super Object, ? extends Object>
        remappingFunction) {
        checkNotReadOnly();
        return super.merge(key, value, remappingFunction);
    }

    @Override
    public synchronized void clear() {
        checkNotReadOnly();
        super.clear();
    }

    @Override
    public synchronized Object setProperty(String key, String value) {
        checkNotReadOnly();
        return super.setProperty(key, value);
    }

    @Override
    public synchronized void load(InputStream inStream) throws IOException {
        checkNotReadOnly();
        super.load(inStream);
    }

    @Override
    public synchronized void load(Reader reader) throws IOException {
        checkNotReadOnly();
        super.load(reader);
    }

    @Override
    public synchronized void loadFromXML(InputStream in) throws IOException {
        checkNotReadOnly();
        super.loadFromXML(in);
    }

    @Override
    protected synchronized void putService(Provider.Service s) {
        checkNotReadOnly();
        super.putService(s);
    }

    @Override
    protected synchronized void removeService(Provider.Service s) {
        checkNotReadOnly();
        super.removeService(s);
    }
}
