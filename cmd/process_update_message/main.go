package main

import (
	"fmt"
	"time"

	"github.com/etclab/art"
)

func main() {
	opts := parseOptions()

	state := art.ProcessUpdateMessage(opts.index, opts.treeStateFile,
		opts.updateMessageFile, opts.macFile)

	state.Save(opts.treeStateFile)
	state.SaveStageKey(fmt.Sprintf("stage-key-process-update-msg-%d-%d.pem",
		opts.index, time.Now().Unix()))
}
