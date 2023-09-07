.PHONY: build
build:
	[ -d build ] || cmake -B build
	cmake --build build --parallel

.PHONY: ninja
ninja:
	[ -d build ] || cmake -B build -G Ninja
	make build

.PHONY: release
release:
	[ -d build ] || cmake -B build -DCMAKE_BUILD_TYPE=Release \
		-DCMAKE_C_FLAGS="-g"
	cmake --build build --parallel

.PHONY: dist
dist: build
	cmake --install build --prefix dist

.PHONY: test
test: build
	cmake --build build --parallel -t retest
	build/test/retest -rv

.PHONY: clean
clean:
	@rm -Rf build dist CMakeCache.txt CMakeFiles
