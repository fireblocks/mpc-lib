all:
	@$(MAKE) -C secp256k1_algebra/ all
	@$(MAKE) -C ed25519_algebra/ all
	@$(MAKE) -C paillier/ all
	@$(MAKE) -C shamir_secret_sharing/ all
	@$(MAKE) -C zero_knowledge_proof/ all
	@$(MAKE) -C drng/ all

clean:
	@$(MAKE) -C secp256k1_algebra/ clean
	@$(MAKE) -C ed25519_algebra/ clean
	@$(MAKE) -C paillier/ clean
	@$(MAKE) -C shamir_secret_sharing/ clean
	@$(MAKE) -C zero_knowledge_proof/ clean
	@$(MAKE) -C drng/ clean

run:
	@$(MAKE) -C secp256k1_algebra/ run
	@$(MAKE) -C ed25519_algebra/ run
	@$(MAKE) -C paillier/ run
	@$(MAKE) -C shamir_secret_sharing/ run
	@$(MAKE) -C zero_knowledge_proof/ run
	@$(MAKE) -C drng/ run
