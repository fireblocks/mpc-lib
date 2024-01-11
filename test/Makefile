all:
	@$(MAKE) -C crypto/ all
	@$(MAKE) -C cosigner/ all
	
clean:
	@rm -rf *.o
	@$(MAKE) -C crypto/ clean
	@$(MAKE) -C cosigner/ clean

run:
	@$(MAKE) -C crypto/ run
	@$(MAKE) -C cosigner/ run
