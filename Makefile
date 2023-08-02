all:
	@$(MAKE) -C src/ all
	@$(MAKE) -C test/ all
	
clean:
	@$(MAKE) -C src/ clean
	@$(MAKE) -C test/ clean

run-tests:
	@$(MAKE) -C test/ run
