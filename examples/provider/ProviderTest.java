/* ProviderTest.java
 *
 * Copyright (C) 2006-2022 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;

import com.wolfssl.provider.jce.WolfCryptProvider;

/**
 * This class tests the wolfSSL provider installation.  It lists all providers
 * installed on the system, tries to look up the wolfSSL provider, and if
 * found, prints out the information about the wolfSSL provider.
 *
 * This app can be useful for testing if wolfJCE has been installed
 * correctly at the system level.
 */
public class ProviderTest {

    /* Print out info about registered Security providers. Does not
     * install wolfJCE. If wolfJCE has been installed at the system
     * level, or application has installed wolfJCE at runtime, it will
     * show up. Otherwise will not. main() below calls this once without
     * installing wolfJCE explicitly, then calls again after installing
     * wolfJCE at runtime as the highest-level provider. */
    public static void pollProviders()
    {
        /* Get all providers */
        Provider [] providers = Security.getProviders();

        System.out.println("\nAll Installed Java Security Providers:");
        System.out.println("---------------------------------------");
        for(Provider prov:providers)
        {
            System.out.println("\t" + prov);
        }

        Provider p = Security.getProvider("wolfJCE");
        if (p == null) {
            System.out.println("No wolfJCE provider registered in system");
        } else {
            /* Test if wolfSSL is a Provider */
            System.out.println("\nInfo about wolfSSL Provider (wolfJCE):");
            System.out.println("----------------------------------------");
            System.out.println("Provider: " + p);
            System.out.println("Info: " + p.getInfo());
            System.out.println("Services:");
            System.out.println(p.getServices());
        }
    }

    public static void main(String args [])
    {
        /* Print system providers before explicit wolfJCE install */
        System.out.println("=================================================");
        System.out.println("| Before installing wolfJCE at runtime          |");
        System.out.println("=================================================");
        pollProviders();

        /* Install wolfJCE */
        Security.insertProviderAt(new WolfCryptProvider(), 1);

        /* Print system provider, after installing wolfJCE */
        System.out.println("");
        System.out.println("=================================================");
        System.out.println("| After installing wolfJCE at runtime           |");
        System.out.println("=================================================");
        pollProviders();
    }
}

