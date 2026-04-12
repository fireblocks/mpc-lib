App_Name := test

App_Common_Flags := -DOPENSSL_API_COMPAT=0x10101000L
App_C_Flags := -g -Wall -Wextra -I../../../../include $(App_Common_Flags) 
App_Cpp_Flags := $(App_C_Flags) -std=c++17 $(App_Common_Flags)
App_Link_Flags := -Wl,-Bstatic -lcrypto -Wl,-Bdynamic -pthread -ldl

all: $(App_Name)

main.o: main.cpp
	@$(CXX) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

algebra_utils.o: ../../../crypto/algebra_utils/algebra_utils.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"


$(App_Name): main.o algebra_utils.o
	@$(CXX) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"

clean:
	@rm -rf $(App_Name) *.o

run:
	./$(App_Name)