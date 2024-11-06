MKDIR=mkdir
CMAKE=cmake
CTEST=ctest

all: build

configure:
	$(MKDIR) -p build
	$(CMAKE) -S . -B build

build: configure
	$(CMAKE) --build build
	
clean: configure
	$(CMAKE) --build build --target clean

run-tests: build
	$(CTEST) --test-dir build
