App_Name := test

App_C_Flags := -g -O0 -Wall -Wextra -I../../../include
App_Cpp_Flags := $(App_C_Flags) -std=c++17
App_Link_Flags := -Wl,-Bstatic -lcrypto -Wl,-Bdynamic -ldl -pthread

all: $(App_Name)

main.o: main.cpp
	@$(CXX) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

drng.o: ../../../src/common/crypto/drng/drng.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

GFp_curve_algebra.o: ../../../src/common/crypto/GFp_curve_algebra/GFp_curve_algebra.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

ed25519_algebra.o: ../../../src/common/crypto/ed25519_algebra/ed25519_algebra.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

keccak1600.o: ../../../src/common/crypto/keccak1600/keccak1600.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

schnorr.o: ../../../src/common/crypto/zero_knowledge_proof/schnorr.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

ring_pedersen.o: ../../../src/common/crypto/commitments/ring_pedersen.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

range_proofs.o: ../../../src/common/crypto/zero_knowledge_proof/range_proofs.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

paillier.o: ../../../src/common/crypto/paillier/paillier.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

diffie_hellman_log.o: ../../../src/common/crypto/zero_knowledge_proof/diffie_hellman_log.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"


$(App_Name): main.o GFp_curve_algebra.o ed25519_algebra.o schnorr.o ring_pedersen.o drng.o range_proofs.o paillier.o diffie_hellman_log.o keccak1600.o
	@$(CXX) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"

clean:
	@rm -rf $(App_Name) *.o

run:
	./$(App_Name)