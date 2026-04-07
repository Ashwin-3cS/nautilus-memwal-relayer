REGISTRY := local
.DEFAULT_GOAL :=
.PHONY: default
default: out/enclaveos.tar

out:
	mkdir out

out/enclaveos.tar: out \
	$(shell git ls-files \
		src/init \
		src/aws \
		src/relayer \
	)
	docker build \
		--tag $(REGISTRY)/enclaveos \
		--progress=plain \
		--platform linux/amd64 \
		--output type=local,rewrite-timestamp=true,dest=out\
		-f Containerfile \
		.

.PHONY: run
run: out/nitro.eif
	sudo nitro-cli \
		run-enclave \
		--cpu-count 2 \
		--memory 4096 \
		--eif-path out/nitro.eif
	@echo ""
	@echo "Enclave running! Now run on the host:"
	@echo "  ./parent_forwarder.sh"
	@echo ""
	@echo "Then test:"
	@echo "  curl http://localhost:4000/health"
	@echo "  curl http://localhost:4000/get_attestation"

.PHONY: run-debug
run-debug: out/nitro.eif
	sudo nitro-cli \
		run-enclave \
		--cpu-count 2 \
		--memory 4096 \
		--eif-path out/nitro.eif \
		--debug-mode \
		--attach-console

.PHONY: run-local
run-local:
	@echo "Running memwal-relayer locally for development..."
	cd src/relayer && cargo run
	@echo "Server at http://localhost:8000"

.PHONY: stop
stop:
	sudo nitro-cli terminate-enclave --all

.PHONY: logs
logs:
	sudo nitro-cli console --enclave-name $$(sudo nitro-cli describe-enclaves | jq -r '.[0].EnclaveID')

.PHONY: status
status:
	@echo "=== ENCLAVE STATUS ==="
	sudo nitro-cli describe-enclaves || echo "No enclaves running"
