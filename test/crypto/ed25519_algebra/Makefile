App_Name := test

App_C_Flags := -g -Wall -Wextra -I../../../include
App_Cpp_Flags := $(App_C_Flags) -std=c++17
App_Link_Flags := -Wl,-Bstatic -lcrypto -Wl,-Bdynamic -pthread -ldl

all: $(App_Name)

main.o: main.cpp
	@$(CXX) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

ed25519_algebra.o: ../../../src/common/crypto/ed25519_algebra/ed25519_algebra.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

keccak1600.o: ../../../src/common/crypto/keccak1600/keccak1600.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

$(App_Name): main.o ed25519_algebra.o keccak1600.o
	@$(CXX) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"

clean:
	@rm -rf $(App_Name) *.o

run:
	./$(App_Name)