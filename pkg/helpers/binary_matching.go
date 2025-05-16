package helpers

import (
	"fmt"
	"os/exec"
	"path/filepath"
)

// BinaryInfo stores information about the located binary
type BinaryInfo struct {
	Name          string
	PathInPATH    string
	RealPath      string
	IsSymlink     bool
	PackageOwner  string
	Distribution  string
	DistVersion   string
	InstallSource string
	Error         error
}

// FindBinary locates a binary and gathers information about it
func FindBinary(name string) BinaryInfo {
	info := BinaryInfo{Name: name}

	path, err := exec.LookPath(name)
	if err != nil {
		info.Error = fmt.Errorf("binary not found in PATH: %v", err)
		return info
	}
	info.PathInPATH = path

	realPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		info.Error = fmt.Errorf("error resolving symlinks: %v", err)
		return info
	}
	info.RealPath = realPath
	info.IsSymlink = (path != realPath)

	return info
}
