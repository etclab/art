package jsonutl

import (
	"encoding/json"
	"os"

	"github.com/syslab-wm/mu"
)

func Encode(fileName string, data interface{}) {
	file, err := os.Create(fileName)
	if err != nil {
		mu.Fatalf("error creating file: %v", err)
	}

	enc := json.NewEncoder(file)
	enc.SetIndent("", "    ")
	enc.Encode(data)

	defer file.Close()
}
