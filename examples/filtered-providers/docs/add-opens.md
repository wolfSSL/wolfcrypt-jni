# JVM module flags for the filtered Sun providers

The filtered providers load the original Sun providers by name and use deep
reflection to copy their non-crypto `Provider.Service` entries. On a modular
JDK (9+) this requires the flags below. The EC-related flags depend on the
JDK version (see the bottom of this file).

## Flags and rationale

- `--add-opens=java.base/java.security=ALL-UNNAMED`
    + Needed by: all three providers
    + Why: reflect into the private `Provider.Service` fields `className`,
      `aliases`, `attributes` (`getDeclaredField` + `setAccessible`).
- `--add-opens=java.base/sun.security.util=ALL-UNNAMED`
    + Needed by: all three providers
    + Why: reflect into the private `string` field of the attribute-key
      class used inside `Provider.Service.attributes`.
- `--add-opens=java.base/sun.security.provider=ALL-UNNAMED`
    + Needed by: `FilteredSun`
    + Why: `Class.forName("sun.security.provider.Sun")` + reflective
      construction of the original `SUN` provider.
- `--add-opens=java.base/sun.security.rsa=ALL-UNNAMED`
    + Needed by: `FilteredSunRsaSign`
    + Why: `Class.forName("sun.security.rsa.SunRsaSign")` + reflective
      construction of the original `SunRsaSign` provider.

The four flags above target `java.base` and should be stable across all
JDK major versions.

## EC flags — version dependent

`sun.security.ec.SunEC` lived in the `jdk.crypto.ec` module through JDK 21,
then moved into `java.base` in JDK 22 (JDK-8308398). `jdk.crypto.ec` still
exists in JDK 22+ as an empty module, deprecated for removal.

**JDK 9–21** (`FilteredSunEC`):

- `--add-modules=jdk.crypto.ec`
    + Resolve the `jdk.crypto.ec` module so `SunEC` is loadable via the
      platform class loader (a service-only module is not in the default
      root set for classpath code).
- `--add-exports=jdk.crypto.ec/sun.security.ec=ALL-UNNAMED`
    + Package access for
      `Class.forName("sun.security.ec.SunEC", true, platformLoader)`.
- `--add-opens=jdk.crypto.ec/sun.security.ec=ALL-UNNAMED`
    + Deep reflection: reflective constructor + the delegating
      `newInstance()` into SunEC internals.

**JDK 22+** (`FilteredSunEC`):

- `--add-exports=java.base/sun.security.ec=ALL-UNNAMED`
    + Package access; SunEC is now in `java.base`.
- `--add-opens=java.base/sun.security.ec=ALL-UNNAMED`
    + Deep reflection into SunEC internals.

On JDK 22+ the EC flags must target `java.base`; flags targeting the (now
empty) `jdk.crypto.ec` module are accepted but have no effect, and the module
may be removed entirely in a future JDK.

The `ant test-filtered-providers` target and the Maven `filtered-providers`
profile select the correct EC flag set automatically based on the running
JDK.

