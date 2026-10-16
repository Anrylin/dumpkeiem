TARGET := iphone:clang:latest:13.0
ARCHS := arm64 arm64e
INSTALL_TARGET_PROCESSES = WeChat

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = DumpKeiem
DumpKeiem_FILES = Tweak.xm
DumpKeiem_CFLAGS = -fobjc-arc
DumpKeiem_FRAMEWORKS = Foundation UIKit

include $(THEOS_MAKE_PATH)/tweak.mk

after-install::
	install.exec "killall -9 WeChat || true"
