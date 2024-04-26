package main

import (
	"fmt"
	"time"

	"github.com/syslab-wm/art"
)

func main() {
	opts := parseOptions()

	state := art.ProcessSetupMessage(opts.index, opts.privEKFile,
		opts.setupMessageFile, opts.initiatorPubIKFile, opts.sigFile)

	state.Save(opts.treeStateFile)
	state.SaveStageKey(fmt.Sprintf("stage-key-process-setup-msg-%d-%d.pem",
		opts.index, time.Now().Unix()))
}
