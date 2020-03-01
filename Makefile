#*******************************************************************************
#*   (c) 2019 Zondax GmbH
#*
#*  Licensed under the Apache License, Version 2.0 (the "License");
#*  you may not use this file except in compliance with the License.
#*  You may obtain a copy of the License at
#*
#*      http://www.apache.org/licenses/LICENSE-2.0
#*
#*  Unless required by applicable law or agreed to in writing, software
#*  distributed under the License is distributed on an "AS IS" BASIS,
#*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#*  See the License for the specific language governing permissions and
#*  limitations under the License.
#********************************************************************************

# We use BOLOS_SDK to determine the develoment environment that is being used
# BOLOS_SDK IS  DEFINED	 	We use the plain Makefile for Ledger
# BOLOS_SDK NOT DEFINED		We use a containerized build approach

ifeq ($(BOLOS_SDK),)
	include $(CURDIR)/deps/ledger-zxlib/cmake/dockerized_build.mk

zemu_install:
	# First unlink everything
	cd js && yarn unlink || true
	cd tests/zemu && yarn unlink @zondax/ledger-zcash || true
	# Now build and link
	cd js && yarn install && yarn build || true
	cd js && yarn link || true
	cd tests/zemu && yarn link @zondax/ledger-zcash || true
	# and now install everything
	cd tests/zemu && yarn install

zemu_upgrade:
	# and now install everything
	cd tests/zemu && yarn install && yarn upgrade --all --latest

zemu_test:
	cd tests/zemu && yarn test

zemu_debug:
	cd tests/zemu/tools && node debug.mjs debug

zemu:
	cd tests/zemu/tools && node debug.mjs

rust_test:
	cd app/rust && cargo test

cpp_test:
	mkdir -p build && cd build && cmake -DDISABLE_DOCKER_BUILDS=ON -DCMAKE_BUILD_TYPE=Debug .. && make
	cd build && GTEST_COLOR=1 ASAN_OPTIONS=detect_leaks=0 ctest -VV

else
default:
	$(MAKE) -C app
%:
	$(info "Calling app Makefile for target $@")
	$(MAKE) -C app $@
endif
