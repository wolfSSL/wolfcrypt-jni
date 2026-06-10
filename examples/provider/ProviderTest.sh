#!/bin/bash

cd ./examples/build/provider
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:../../../lib/:/usr/local/lib
java -classpath ../../../lib/wolfcrypt-jni.jar:./ -Dsun.boot.library.path=../../../lib/ -Dwolfjce.debug=true ProviderTest $@

