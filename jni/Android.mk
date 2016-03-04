ROOT_PATH := $(call my-dir)

################################################################################

include $(CLEAR_VARS)

LOCAL_MODULE    := libwolfssl
LOCAL_PATH      := ../../src/.libs
LOCAL_SRC_FILES := libwolfssl.a

include $(PREBUILT_STATIC_LIBRARY)

################################################################################

include $(CLEAR_VARS)

LOCAL_MODULE     := libwolfcrypt-jni
LOCAL_PATH       := $(ROOT_PATH)
LOCAL_C_INCLUDES := $(LOCAL_PATH)/include ../../../wolfssl
LOCAL_SRC_FILES  := jni_fips.c \
					jni_native_struct.c \
					jni_aes.c \
					jni_des3.c \
					jni_md5.c \
					jni_sha.c \
					jni_hmac.c \
					jni_rng.c \
					jni_rsa.c \
					jni_dh.c \
					jni_ecc.c \
					jni_asn.c \
					jni_logging.c

LOCAL_CFLAGS     := -DHAVE_CONFIG_H -Wall -Wno-unused
LOCAL_LDLIBS     := -llog

LOCAL_STATIC_LIBRARIES := libwolfssl

include $(BUILD_SHARED_LIBRARY)

################################################################################

