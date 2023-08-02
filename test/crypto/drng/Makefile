App_Name := test

App_C_Flags := -g -Wall -Wextra -I../../../include
App_Cpp_Flags := $(App_C_Flags) -std=c++17
App_Link_Flags := -lcrypto

all: $(App_Name)

main.o: main.cpp
	@$(CXX) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

drng.o: ../../../src/common/crypto/drng/drng.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

$(App_Name): main.o drng.o
	@$(CXX) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"

clean:
	@rm -rf $(App_Name) *.o

run:
	./$(App_Name)