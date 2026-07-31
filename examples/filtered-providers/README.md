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
only place that controls which services pass through. Edit, rebuild, and
redeploy if you need to do something different than the default behavior.

To grant exceptions for individual services without recompiling, see
[Allowing additional services](#allowing-additional-services-through-the-filter)
below.

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

This is a Security property (not System property), read at provider
construction time. It can also be set with `Security.setProperty()` before
the providers are first instantiated. `security.overridePropertiesFile=false`
blocks an alternate properties file (`-Djava.security.properties`), though
early `Security.setProperty()` calls still apply.

Pros (why enable it):

- Legacy application code and third-party jars that pin the original provider
  names work unmodified (ex: `CertificateFactory.getInstance("X.509", "SUN")`).
- OpenJDK code paths that internally look up Sun providers by name keep
  resolving, without patching.
- No application-side try/catch fallback shims are needed for the allow-listed
  services.

Cons (why the default uses the `Filtered*` provider names):

- A hardened provider masquerading as the stock one can hide the hardening
  from inspection: monitoring that records only `Provider.getName()` sees `SUN`
  on both stock and hardened JREs. Use `Provider.getInfo()` or the provider
  class name to distinguish them.
- With the default `Filtered*` names, a pinned lookup fails with
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

## Allowing additional services through the filter

Some JDK and application code depends on non-FIPS-validated algorithms, and
sometimes FIPS-specific exceptions have been made in those cases. One example
offender is `java.util.UUID.nameUUIDFromBytes()`, which calls
`MessageDigest.getInstance("MD5")` and throws `InternalError` if no registered
provider offers MD5, so on a hardened image any code generating name-based
(version 3) UUIDs fails at startup.

To grant exceptions for individual services without recompiling, set the
per-provider `additionalServices` Security properties to a comma-separated
list of `Type.Algorithm` entries, ex:

```
wolfssl.filtered.sun.additionalServices=MessageDigest.MD5
wolfssl.filtered.sunec.additionalServices=
wolfssl.filtered.sunrsasign.additionalServices=
```

With the example above, `FilteredSun` also copies `MessageDigest.MD5` from
the original `SUN` provider, and `UUID.nameUUIDFromBytes()` works again. The
grant is exact: only the listed algorithm passes through, not the whole
service type.

Entry semantics:

- Entries are split on the **first** `.` into a service type and an algorithm,
  because algorithm names can themselves contain dots
  (ex: `CertStore.com.sun.security.IndexedCollection`).
- Matching is case-insensitive against canonical names. Aliases cannot specify
  a grant. A granted service keeps its original aliases and stays reachable
  under them (ex: the MD5 OID `1.2.840.113549.2.5`), the same as the
  compiled-in allow-list services.
- Malformed entries (no dot, empty type, or empty algorithm) are ignored.
- Like `wolfssl.filtered.useOriginalNames`, these are Security properties
  (not System properties), read at provider construction time.
  `security.overridePropertiesFile=false` blocks an alternate properties
  file (`-Djava.security.properties`), but application code running before
  the providers are first instantiated can still change them with
  `Security.setProperty()`.
- These properties are independent of `wolfssl.filtered.useOriginalNames`.

Pros (why grant exceptions this way):

- Code that requires a non-validated algorithm for a non-security purpose
  (ex: version 3 UUIDs) works without application changes or re-enabling
  the algorithm in the wolfCrypt build.
- The granted algorithm is served by the JDK's pure-Java Sun implementation,
  keeping it outside the validated wolfCrypt module boundary.
- The exception list is an auditable line in `java.security`, reviewable
  in image diffs and enumerable at runtime via `Provider.getServices()`.

Cons (why the default grants nothing):

- A granted service is reachable by **any** code in the JVM, not only the
  caller it was granted for. Grants must be deliberate and meaningful due to
  potential use of non-FIPS validated cryptography.
- Each entry widens the audited service surface. Compliance sign-off should
  cover every entry and the reason it is needed.
- Wildcards are deliberately not supported, so the granted surface stays
  explicitly enumerable.

## Common configuration mistakes

The properties above fail closed: a value that does not parse leaves the
default behavior in place. The providers warn to stderr at construction time
for mistakes they can detect. A correct configuration prints nothing.

- `#` starts a comment only at the beginning of a line in `java.security`,
  so `wolfssl.filtered.useOriginalNames=true # on` sets the value to
  `true # on`, which is unrecognized (treated as `false`). Same for
  `additionalServices` entries.
- Do not quote values: `="MessageDigest.MD5"` includes the quote characters
  and matches nothing.
- Use canonical `Type.Algorithm` names in grants. Aliases and OID forms
  (ex: `MessageDigest.1.2.840.113549.2.5`) never match an entry.
- Grants are per provider: `KeyFactory.EC` belongs in
  `wolfssl.filtered.sunec.additionalServices`, not `...sun...`. An entry
  matching no service of the wrapped provider is ignored.
- `wolfssl.filtered.useOriginalNames` and the `additionalServices` properties
  are Security properties. Setting them with `-D` (ex: via
  `JAVA_TOOL_OPTIONS`) creates an ignored system property. The exception is
  `wolfssl.filtered.debug`, a system property that must be set with `-D`.
- Property keys are case-sensitive and fixed lowercase:
  `wolfssl.filtered.sunec.additionalServices`, never `...SunEC...`.
- Long values need a trailing `\` to continue on the next line. Without it the
  continuation becomes a different, silently ignored property.
- Keep `security.provider.N` numbering consecutive from 1. The JDK stops
  reading at the first gap and silently ignores later entries.
- Register the providers by *their* class names only. Both
  `security.provider.N=SUN` and `=sun.security.provider.Sun` load the
  stock Sun provider through a hardcoded JDK fast path, and the name form
  `security.provider.N=FilteredSun` stops resolving once
  `wolfssl.filtered.useOriginalNames=true` is set (the JDK matches the
  entry against the resolved name, then `SUN`).
- On images with `security.overridePropertiesFile=false`,
  `-Djava.security.properties` has no effect. Edit the image `java.security`
  file instead.
- If a provider is missing at runtime, check stderr for constructor failures
  (ex: missing `--add-opens` flags) and rerun with
  `-Djava.security.debug=provider`. The JDK swallows provider construction
  errors silently.

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

