package jsonutl

import (
	"art/internal/mu"
	"encoding/json"
	"os"
)

func Encode(fileName string, data interface{}) {
	file, err := os.Create(fileName)
	if err != nil {
		mu.Die("error creating file: %v", err)
	}

	enc := json.NewEncoder(file)
	enc.SetIndent("", "    ")
	enc.Encode(data)

	defer file.Close()
}
