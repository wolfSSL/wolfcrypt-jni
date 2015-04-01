OUT_PATH  = lib
SRC_PATH  = jni
INC_PATH  = $(SRC_PATH)/include

OBJ_LIST  = jni_fips.o jni_native_struct.o jni_aes.o jni_des3.o jni_sha.o \
			jni_hmac.o jni_rng.o jni_rsa.o jni_asn.o
OBJS      = $(patsubst %,$(OUT_PATH)/%,$(OBJ_LIST))
TARGET    = $(OUT_PATH)/libwolfcrypt-jni.jnilib

JAVA_HOME = $(shell /usr/libexec/java_home)
CC        = gcc
CCFLAGS   = -Wall -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/darwin \
			-I$(INC_PATH) -DHAVE_FIPS
LDFLAGS   = -dynamiclib -framework JavaVM -lwolfssl

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CCFLAGS) $(LDFLAGS) -o $@ $^

$(OUT_PATH)/%.o: $(SRC_PATH)/%.c
	$(CC) $(CCFLAGS) -c -o $@ $<

.PHONY: clean

clean:
	rm -f $(OUT_PATH)/*.o $(TARGET)