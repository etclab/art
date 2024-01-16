progs= genpkey pkeyutl groupsetup processmsg

all: $(progs)

$(progs):
	go build ./cmd/$@

fmt:
	go fmt ./...

vet:
	go vet ./...

clean:
	rm -f $(progs)

.PHONY: $(progs) all fmt vet clean
