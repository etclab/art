package mu

import (
	"fmt"
	"log"
	"os"
	"strings"
)

var Debug = false

func Dlogf(format string, a ...any) {
	if !Debug {
		return
	}
	if !strings.HasSuffix(format, "\n") {
		format += "\n"
	}
	log.Printf(format, a...)
}

func Die(format string, a ...any) {
	if !strings.HasSuffix(format, "\n") {
		format += "\n"
	}
	fmt.Fprintf(os.Stderr, format, a...)
	os.Exit(1)
}

func Panicf(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	panic(msg)
}
