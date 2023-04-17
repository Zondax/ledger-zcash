#*******************************************************************************
#  Ledger App
#  (c) 2018 - 2023 Zondax AG
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
APPNAME = "Zcash"
APPPATH = "44'/133'"
else
define error_message
COIN value not supported: [$(COIN)]
endef
$(error "$(error_message)")
endif

APP_LOAD_PARAMS = --curve secp256k1 $(COMMON_LOAD_PARAMS) --path $(APPPATH)

NANOS_STACK_SIZE := 3216
include $(CURDIR)/../deps/ledger-zxlib/makefiles/Makefile.devices

$(info TARGET_NAME  = [$(TARGET_NAME)])
$(info ICONNAME  = [$(ICONNAME)])

ifndef ICONNAME
$(error ICONNAME is not set)
endif

include $(CURDIR)/../deps/ledger-zxlib/makefiles/Makefile.platform

DEFINES		  += HAVE_HASH HAVE_BLAKE2 HAVE_SHA256 HAVE_SHA512
APP_SOURCE_PATH += $(CURDIR)/rust/include
APP_SOURCE_PATH += $(MY_DIR)/../deps/tiny-aes/src

LDFLAGS += -z muldefs
LDLIBS += -Lrust/target/thumbv6m-none-eabi/release -lrslib

APP_CUSTOM_LINK_DEPENDENCIES = rust

.PHONY: rust
rust:
	cd rust && CARGO_HOME="$(CURDIR)/rust/.cargo" cargo build --target thumbv6m-none-eabi --release

# Before linking, we need to be sure rust lib is there
bin/app.elf: rust

.PHONY: rust_clean
rust_clean:
	cd rust && CARGO_HOME="$(CURDIR)/rust/.cargo" cargo clean

clean: rust_clean

# load, delete and listvariants are provided to comply with Ledger requirements
.PHONY: load
load:
	python3 -m ledgerblue.loadApp $(APP_LOAD_PARAMS)

.PHONY: delete
delete:
	python3 -m ledgerblue.deleteApp $(COMMON_DELETE_PARAMS)

# Import generic rules from the SDK
include $(BOLOS_SDK)/Makefile.rules

#add dependency on custom makefile filename
dep/%.d: %.c Makefile

.PHONY: listvariants
listvariants:
	@echo VARIANTS COIN ZEC

.PHONY: version
version:
	@echo "v$(APPVERSION)" > app.version
