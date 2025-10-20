# Building wolfCrypt JNI/JCE (wolfcryptjni)
- If on Linux "cp makefile.linux makefile", if on macOS "cp makefile.macosx makefile"
- To build the native JNI shared library run "make"
- To build the Java JAR library and examples run "ant build-jce-debug"

# Running JUnit tests
- To run JUnit tests run "ant test"
- All tests should pass without problems

# Code Style
- Keep lines under 80 characters maximum length
- MUST only use multi-line comments, no "//" style ones
- MUST remove all trailing white space
- MUST use 4 spaces for one tab, no hard tabs
- MUST use XMALLOC/XFREE for memory allocation instead of malloc/free
- MUST cast XMALLOC back to type being allocated

# Source Code Organization
- The source code is organized into the following directories:
  + jni: JNI source files
  + jni/include: JNI header files
  + src/main/java: Java source code
  + src/main/java/com/wolfssl/wolfcrypt: com.wolfssl.wolfcrypt package JNI layer source code
  + src/main/java/com/wolfssl/provider/jce: com.wolfssl.provider.jce package wolfCrypt JCE provider source code
  + src/test: JUnit test code
  + src/test/java/com/wolfssl/wolfcrypt/test: com.wolfssl.wolfcrypt thin JNI wrapper JUnit test code
  + src/test/java/com/wolfssl/provider/jce/test: com.wolfssl.provider.jce wolfCrypt JCE provider JUnit test code
  + build.xml: Ant build file
  + pom.xml: Maven build file
  + docs: Documentation files
  + docs/design: Design files
  + docs/javadoc: Generated Javadoc file location
  + scripts/infer.sh: Script to run Facebook Infer static analysis
  + IDE/Android: Android Studio example project files
  + IDE/WIN: Visual Studio solution file
  + examples: examples directory

# Workflow
- Make sure package compiles and all JUnit tests pass when you are making code changes
- Maintain minimum Java compatibility down to Java 8

# Example Code Guidelines for Writing New Code
- All examples are placed under the "examples" directory
- Directory "examples" contains JNI-level examples
- Directory "examples/provider" contains JCE-level examples
- All examples should have two files:
  + Example.java: Java source code
  + Example.sh: Shell script to run the example
- Examples will be run from the root directory
- Example .jks files are located under "examples/certs"
- Example .wk files are located under "examples/certs"
- Example .jks files are updated using the update-jks-wks.sh script

# Adding new JUnit test files
- All new wolfCrypt JUnit test files must be added to src/test/java/com/wolfssl/wolfcrypt/test/WolfCryptTestSuite.java
- All new wolfJCE JUnit test files must be added to src/test/java/com/wolfssl/provider/jce/test/WolfJCETestSuite.java
- New JUnit test classes must define TestRule like existing ones do

# Adding new Java files
- MUST add all new JNI or JCE Java files to scripts/infer.sh for Infer static analysis
