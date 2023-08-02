COMMON_CFLAGS := -m64 -fPIC -march=skylake -Wall -Wextra -Wvla -Wswitch-enum -Wno-missing-field-initializers -fdiagnostics-color=always
DEBUG ?= 1

ifeq ($(DEBUG), 1)
	COMMON_CFLAGS += -O0 -g -Werror -Wformat -Wformat-security
else
	COMMON_CFLAGS += -O3 -DNDEBUG -UEDEBUG -UDEBUG
endif

COMMON_CFLAGS := $(COMMON_CFLAGS)

C_Files := crypto/shamir_secret_sharing/verifiable_secret_sharing.c crypto/paillier/paillier.c crypto/paillier/paillier_zkp.c crypto/GFp_curve_algebra/GFp_curve_algebra.c \
				   crypto/commitments/commitments.c crypto/zero_knowledge_proof/schnorr.c crypto/zero_knowledge_proof/range_proofs.c crypto/zero_knowledge_proof/diffie_hellman_log.c \
				   crypto/commitments/ring_pedersen.c crypto/ed25519_algebra/ed25519_algebra.c crypto/drng/drng.c crypto/keccak1600/keccak1600.c
				   
C_Objects := $(C_Files:.c=.o)

Cpp_Files := cosigner/cosigner_exception.cpp cosigner/cmp_setup_service.cpp cosigner/cmp_offline_refresh_service.cpp cosigner/utils.cpp \
	cosigner/cmp_ecdsa_signing_service.cpp cosigner/cmp_ecdsa_online_signing_service.cpp cosigner/cmp_ecdsa_offline_signing_service.cpp cosigner/mta.cpp \
	cosigner/eddsa_online_signing_service.cpp cosigner/asymmetric_eddsa_cosigner.cpp cosigner/asymmetric_eddsa_cosigner_server.cpp cosigner/asymmetric_eddsa_cosigner_client.cpp \
	blockchain/mpc/hd_derive.cpp

Cpp_Objects := $(Cpp_Files:.cpp=.o)

Include_Paths := -I. -I../../include

C_Flags := $(COMMON_CFLAGS) -fstack-protector-strong
C_Flags += $(Include_Paths)
C_Flags += -Wno-unknown-pragmas

Cpp_Flags := $(C_Flags) -std=c++17 -Wno-overloaded-virtual

Link_Flags := $(COMMON_CFLAGS) -shared -Wl,--version-script=lib.lds -Wl,--no-undefined -Wl,-Bstatic -lcrypto -Wl,-Bdynamic -lpthread -ldl

Lib_Name := libcosigner.so

.PHONY: all

all: $(Lib_Name)

$(C_Objects): %.o: %.c
	@$(CC) $(C_Flags) -c $< -o $@
	@echo "CC  <=  $<"

$(Cpp_Objects): %.o: %.cpp
	@$(CXX) $(Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(Lib_Name): $(Cpp_Objects) $(C_Objects) lib.lds
	@$(CXX) $(Cpp_Objects) $(C_Objects) -o $@ $(Link_Flags)
	@echo "LINK =>  $@"

clean:
	@rm -fR $(Lib_Name) $(Cpp_Objects) $(C_Objects)
