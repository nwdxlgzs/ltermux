LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_C_INCLUDES += $(LOCAL_PATH)/../lua
LOCAL_MODULE     := ltermux
LOCAL_SRC_FILES  := termux.c
LOCAL_STATIC_LIBRARIES := luajava
LOCAL_LDLIBS += -llog

include $(BUILD_SHARED_LIBRARY)

