App_Name := test

App_C_Flags := -g -I../../include -DTEST_ONLY
App_Cpp_Flags := $(App_C_Flags) -std=c++17
App_Link_Flags := -L../../src/common -lcosigner -Wl,-Bstatic -lcrypto -Wl,-Bdynamic -luuid -lsecp256k1 -pthread -ldl

App_Cpp_Files := $(wildcard ./*.cpp)
App_Cpp_Objects := $(App_Cpp_Files:.cpp=.o)

OLD_LD_PATH := $(LD_LIBRARY_PATH)

all: $(App_Name)

cosigner:
	@$(MAKE) -C ../../src/

$(App_Cpp_Objects): %.o: %.cpp
	@$(CXX) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(App_Name): $(App_Cpp_Objects) cosigner
	@$(CXX) $(App_Cpp_Objects) -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"

clean:
	@rm -rf $(App_Name) *.o

run: all
	@export LD_LIBRARY_PATH=../../src/common/ && ./test
