App_Name := test

App_C_Flags := -g -Wall -Wextra -I../../../include
App_Cpp_Flags := $(App_C_Flags) -std=c++17
App_Link_Flags := -Wl,-Bstatic -lcrypto -Wl,-Bdynamic -pthread -ldl

all: $(App_Name)

tests.o: tests.cpp
	@echo "CXX  <=  $<"
	@$(CXX) $(App_Cpp_Flags) -c $< -o $@

../../tests_main.o: ../../tests_main.cpp
	@$(CXX) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

ed25519_algebra.o: ../../../src/common/crypto/ed25519_algebra/ed25519_algebra.c
	@echo "CC   <=  $<"
	@$(CC) $(App_C_Flags) -c $< -o $@

keccak1600.o: ../../../src/common/crypto/keccak1600/keccak1600.c
	@echo "CC   <=  $<"
	@$(CC) $(App_C_Flags) -c $< -o $@

$(App_Name): tests.o ../../tests_main.o ed25519_algebra.o keccak1600.o
	@echo "LINK =>  $@"
	@$(CXX) $^ -o $@ $(App_Link_Flags)

clean:
	@rm -rf $(App_Name) *.o

run:
	./$(App_Name)