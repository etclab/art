progs= genpkey pkeyutl setup_group process_setup_message update_key process_update_message

all:  $(progs)

$(progs): % : vet
	go build ./cmd/$@

vet: fmt
	go vet ./...

fmt:
	go fmt ./...

clean:
	rm -f $(progs)

.PHONY: all vet fmt clean
