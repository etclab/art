package main

import (
	"os"
	"path/filepath"

	"github.com/etclab/art"
	"github.com/etclab/mu"
)

func main() {
	opts := parseOptions()

	state, setupMsg := art.SetupGroup(opts.configFile, opts.initiator)

	err := os.MkdirAll(opts.outDir, 0750)
	if err != nil {
		mu.Fatalf("error: can't create out-dir: %v", err)
	}

	setupMsg.Save(opts.msgFile)
	setupMsg.SaveSign(opts.sigFile, opts.msgFile, opts.privIKFile)

	state.Save(opts.treeStateFile)
	state.SaveStageKey(filepath.Join(opts.outDir, "stage-key.pem"))
}
