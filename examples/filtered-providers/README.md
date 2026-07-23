# Filtered Sun Security Providers

Custom JCE/JSSE providers that wrap the JDK's `SUN`, `SunEC`, and `SunRsaSign`
providers and expose **only their non-cryptographic services**. The original
crypto algorithms are dropped; the supporting non-crypto services that
wolfJCE/wolfJSSE depend on are kept:

- `FilteredSun` retains:
    + `CertStore.Collection`
    + `CertStore.com.sun.security.IndexedCollection`
    + `CertificateFactory.X.509`
    + `Configuration.JavaLoginConfig`
    + `Policy.JavaPolicy`
- `FilteredSunEC` retains:
    + `AlgorithmParameters.EC`
- `FilteredSunRsaSign` retains:
    + `KeyFactory.RSASSA-PSS`

These are used in hardened JREs, like wolfSSL's FIPS 140-3 Java containers,
where non-FIPS validated Sun crypto must be removed but the non-crypto services
above are still needed. For a complete integration example (Docker base image,
java.security configuration, entrypoint), see the wolfSSL containers repository:
https://github.com/wolfSSL/wolfssl-containers

**Requires Java 9+.** The providers use `ClassLoader.getPlatformClassLoader()`
and deep reflection into JDK internals
(see [docs/add-opens.md](docs/add-opens.md)). They are **not** part of the
published `wolfcrypt-jni.jar`; they ship as source under this directory and
build into a standalone jar.

## Build

The providers build automatically with the normal project builds when running
a supported JDK (Java 9+), and are skipped automatically on Java 8. No profile
or extra flags needed:

```
# Ant: built as part of 'ant build-jce-debug' / 'ant build-jce-release',
# or standalone. Produces:
#     lib/filtered-providers/filtered-providers.jar
ant examples-filtered-providers

# Maven: built as part of 'mvn package'. Produces
#     target/wolfcrypt-jni-<version>-filtered-providers.jar
mvn package
```

Both jars are self-contained and include a
`META-INF/services/java.security.Provider` entry so the providers can also be
discovered via `ServiceLoader`.

## Pulling into your own Linux host, VM, or container

The build produces a single self-contained jar. Copy it out and drop it onto
your system:

1. Copy the jar onto the classpath, e.g.:

   ```
   cp filtered-providers.jar /usr/share/java/
   ```

2. Register the providers in `$JAVA_HOME/conf/security/java.security`
   (replacing the original `SUN` / `SunEC` / `SunRsaSign` entries):

   ```
   security.provider.N   = com.wolfssl.security.providers.FilteredSun
   security.provider.N+1 = com.wolfssl.security.providers.FilteredSunEC
   security.provider.N+2 = com.wolfssl.security.providers.FilteredSunRsaSign
   ```

   (Both jars also register the providers via `META-INF/services` for
   `ServiceLoader`-based discovery.)

3. Add the required JVM module flags. The EC flags **differ by JDK version**
   because SunEC moved from the `jdk.crypto.ec` module into `java.base` in
   JDK 22:

   **JDK 9–21:**

   ```
   --add-modules=jdk.crypto.ec
   --add-exports=jdk.crypto.ec/sun.security.ec=ALL-UNNAMED
   --add-opens=jdk.crypto.ec/sun.security.ec=ALL-UNNAMED
   --add-opens=java.base/java.security=ALL-UNNAMED
   --add-opens=java.base/sun.security.provider=ALL-UNNAMED
   --add-opens=java.base/sun.security.util=ALL-UNNAMED
   --add-opens=java.base/sun.security.rsa=ALL-UNNAMED
   ```

   **JDK 22+:**

   ```
   --add-exports=java.base/sun.security.ec=ALL-UNNAMED
   --add-opens=java.base/sun.security.ec=ALL-UNNAMED
   --add-opens=java.base/java.security=ALL-UNNAMED
   --add-opens=java.base/sun.security.provider=ALL-UNNAMED
   --add-opens=java.base/sun.security.util=ALL-UNNAMED
   --add-opens=java.base/sun.security.rsa=ALL-UNNAMED
   ```

   For Docker/Kubernetes, set these via `JAVA_TOOL_OPTIONS`. See
   [docs/add-opens.md](docs/add-opens.md) for the per-flag rationale.

4. Optional debug logging:

   ```
   -Dwolfssl.filtered.debug=true
   ```

## Customizing the filter

Each `Filtered*.java` has a single `serviceSupported()` method, which is the
only place that controls which services pass through. Edit it, rebuild, and
redeploy if you need to do something different.

## Using the original Sun provider names

Some legacy code, OpenJDK code, or other libraries may hardcode specific
provider names, such as:

```java
CertificateFactory.getInstance("X.509", "SUN");
```

With the filtered providers registered under their default names, those calls
will throw `NoSuchProviderException` because the `SUN` providers may have been
purposefully unregistered for FIPS compliance.

To keep this type of code working, the `wolfssl.filtered.useOriginalNames`
Security property can be set to `true` and the filtered providers will register
under the original provider names that they are filtering instead of their
`Filtered*` names.

```
wolfssl.filtered.useOriginalNames=true
```

This is a Security property (not System property), and is read at provider
construction time, so it can also be set programmatically with
`Security.setProperty()` as long as that happens before the providers are first
instantiated. On images that set `security.overridePropertiesFile=false` the
value is fixed by the image's `java.security` file and cannot be changed from
the command line.

Pros (why enable it):

- Legacy application code and third-party jars that pin the original
  provider names work unmodified, e.g.
  `CertificateFactory.getInstance("X.509", "SUN")`.
- OpenJDK code paths that internally look up Sun providers by name keep
  resolving, without patching or shading.
- No application-side try/catch fallback shims are needed for the
  allow-listed services.

Cons (why the default leaves the `Filtered*` names):

- A hardened provider masquerading as the stock one can hide the hardening
  from casual inspection: monitoring that records only `Provider.getName()`
  sees `SUN` on both stock and hardened JREs. Use `Provider.getInfo()` or the
  provider class name to distinguish them.
- With the default `Filtered*` names, a pinned lookup fails loudly with
  `NoSuchProviderException` at the exact call site that needs fixing. Enabling
  the name override trades that diagnosability for compatibility.
- The original providers must not also be registered. If both the real `SUN`
  and a filtered provider named `SUN` end up registered, lookups resolve to
  whichever is first in the provider order.
- Always register by class name (`security.provider.N =
  com.wolfssl.security.providers.FilteredSun`). Class-name registration is
  unaffected by the name change. Registration by provider *name*
  (`security.provider.N = SUN`) must not be used with this feature: the JDK
  resolves the built-in provider names internally before consulting classpath
  providers, so a `SUN`/`SunEC`/`SunRsaSign` entry always loads the stock Sun
  provider, silently bypassing the filtered one and reinstating the
  non-validated crypto regardless of this property.

## Tests

The filtered-providers tests run automatically on JDK 9+ alongside the main
test suite, or can be run standalone.

```
# Ant: Java 9+ only (no-op on Java 8)
ant test-filtered-providers

# Maven: run only the filtered-providers tests (skips the main suite)
mvn test -Dmain.tests.skip=true
```

## Java 8

Not supported. The reflection model and class loading depend on Java 9+
module system APIs. Both the ant targets and the Maven profile skip
automatically on Java 8 (the Maven profile activates only on JDK 9+).

