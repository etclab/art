package mu

import (
	"os"
	"path/filepath"
)

func FileSize(path string) (int64, error) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return fileInfo.Size(), nil
}

func isRegular(path string) (bool, error) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	return fileInfo.Mode().IsRegular(), nil
}

func IsDir(path string) (bool, error) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	return fileInfo.Mode().IsDir(), nil
}

// ResolvePath resolves the rel path relative to the start path.
// The resolution is purely lexical.
func ResolvePath(rel, start string) string {
	if filepath.IsAbs(rel) {
		return rel
	}
	dir := filepath.Dir(start)
	file := filepath.Base(rel)
	return filepath.Join(dir, file)
}
