OUT_PATH  = lib
SRC_PATH  = jni
INC_PATH  = $(SRC_PATH)/include

OBJ_LIST  = jni_fips.o jni_native_struct.o jni_aes.o jni_des3.o jni_md5.o \
			jni_sha.o jni_hmac.o jni_rng.o jni_rsa.o jni_dh.o jni_ecc.o \
			jni_error.o jni_asn.o jni_logging.o
OBJS      = $(patsubst %,$(OUT_PATH)/%,$(OBJ_LIST))
TARGET    = $(OUT_PATH)/libwolfcryptjni.so

JAVA_HOME = $(shell readlink -f /usr/bin/javac | sed "s:/bin/javac::")
CC        = gcc
override CCFLAGS   += -Wall -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/linux \
			-I$(INC_PATH) -fPIC
override LDFLAGS   += -Wl,--no-as-needed -lwolfssl -shared

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CCFLAGS) $(LDFLAGS) -o $@ $^

$(OUT_PATH)/%.o: $(SRC_PATH)/%.c
	@mkdir -p $(OUT_PATH)
	$(CC) $(CCFLAGS) -c -o $@ $<

.PHONY: clean

clean:
	rm -f $(OUT_PATH)/*.o $(TARGET)
