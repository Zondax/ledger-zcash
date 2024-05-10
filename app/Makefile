#*******************************************************************************
#  Ledger App
#  (c) 2018 - 2024 Zondax AG
#  (c) 2017 Ledger
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#*******************************************************************************

ifeq ($(BOLOS_SDK),)
$(error BOLOS_SDK is not set)
endif

MY_DIR := $(dir $(lastword $(MAKEFILE_LIST)))

include $(CURDIR)/../deps/ledger-zxlib/makefiles/Makefile.installer_script

include $(BOLOS_SDK)/Makefile.defines

$(info ************ TARGET_NAME  = [$(TARGET_NAME)])

include $(CURDIR)/../deps/ledger-zxlib/makefiles/Makefile.app_testing

ifndef COIN
COIN=ZEC
endif

include $(CURDIR)/Makefile.version

$(info COIN  = [$(COIN)])

ifeq ($(COIN),ZEC)
# Main app configuration
APPNAME = "Zcash Shielded"
APPPATH = "44'/133'" --path "44'/1'"

else
define error_message

COIN value not supported: [$(COIN)]

endef
$(error "$(error_message)")
endif

APP_LOAD_PARAMS = --curve secp256k1 --curve ed25519 $(COMMON_LOAD_PARAMS) --path $(APPPATH)

include $(CURDIR)/../deps/ledger-zxlib/makefiles/Makefile.devices

$(info TARGET_NAME  = [$(TARGET_NAME)])
$(info ICONNAME  = [$(ICONNAME)])

ifndef ICONNAME
$(error ICONNAME is not set)
endif

include $(CURDIR)/../deps/ledger-zxlib/makefiles/Makefile.platform

# Add SDK BLAKE2b
DEFINES		  += HAVE_HASH HAVE_BLAKE2 HAVE_SHA256 HAVE_SHA512 HAVE_ZIP0317
INCLUDES_PATH += $(BOLOS_SDK)/lib_cxng/src
APP_SOURCE_PATH += $(CURDIR)/rust/include
APP_SOURCE_PATH += $(MY_DIR)/../deps/tiny-aes/src

# Existing CFLAGS
CFLAGS += -Werror
CXXFLAGS += -Werror

# Building Rust
LDFLAGS += -z muldefs
LDLIBS += -L$(MY_DIR)rust/target/$(RUST_TARGET)/release -lrslib

APP_SOURCE_PATH += $(CURDIR)/rust/include
APP_CUSTOM_LINK_DEPENDENCIES = rust
RUST_TARGET:=thumbv6m-none-eabi

.PHONY: rust
rust:
	cd rust && RUSTC_BOOTSTRAP=1 CARGO_HOME="$(CURDIR)/rust/.cargo" cargo build --target $(RUST_TARGET) --release

.PHONY: rust_clean
rust_clean:
	cd rust && CARGO_HOME="$(CURDIR)/rust/.cargo" cargo clean

clean: rust_clean

include $(CURDIR)/../deps/ledger-zxlib/makefiles/Makefile.side_loading

# Import generic rules from the SDK
include $(BOLOS_SDK)/Makefile.rules

#add dependency on custom makefile filename
dep/%.d: %.c Makefile

listvariants:
	@echo VARIANTS COIN ZEC

.PHONY: version
version:
	@echo "v$(APPVERSION)" > app.version
