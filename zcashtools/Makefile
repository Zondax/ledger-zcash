build_web: 
	rm -rf pkg
	CC=/usr/local/opt/llvm/bin/clang AR=/usr/local/opt/llvm/bin/llvm-ar wasm-pack build --target web
	node scripts/post_build.js pkg zcashtool.js params/sapling-output.params params/sapling-spend.params pkg/zcashtool_bg.wasm
	rm -rf pkg/zcashtool_bg.wasm

build_nodejs: 
	rm -rf pkg
	CC=/usr/local/opt/llvm/bin/clang AR=/usr/local/opt/llvm/bin/llvm-ar wasm-pack build --target nodejs
	node scripts/post_build.js pkg zcashtool.js params/sapling-output.params params/sapling-spend.params pkg/zcashtool_bg.wasm
	rm -rf pkg/zcashtool_bg.wasm

publish_web_local: build_web
	cd pkg && yalc publish


publish_nodejs_local: build_nodejs
	cd pkg && yalc publish