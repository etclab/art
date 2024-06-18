package main

import (
	"fmt"
	"time"

	"github.com/etclab/art"
)

func main() {
	opts := parseOptions()

	updateMsg, state, stageKey := art.UpdateKey(opts.index, opts.treeStateFile)

	updateMsg.Save(opts.updateFile)
	updateMsg.SaveMac(*stageKey, opts.macFile)

	state.Save(opts.treeStateFile)
	state.SaveStageKey(fmt.Sprintf("stage-key-update-key-%d-%d.pem",
		opts.index, time.Now().Unix()))
}
