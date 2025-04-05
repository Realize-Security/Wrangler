package files

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"strconv"
)

const permissions = 0600

func FileLinesToSlice(path string) ([]string, error) {
	var result []string
	file, err := os.Open(path)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		result = append(result, line)
	}

	if err := scanner.Err(); err != nil {
		fmt.Println(err)
		return nil, err
	}
	return result, nil
}

func WriteSliceToFile(projectRoot, scopeDirectory, filename string, targets []string) (string, error) {
	err := CreateDir(scopeDirectory)
	if err != nil {
		return "", fmt.Errorf("unable to create directory: %s", err.Error())
	}

	fullPath := path.Join(projectRoot, scopeDirectory, filename)
	err = WriteFile(fullPath, targets)
	if err != nil {
		return "", fmt.Errorf("unable to create file: %s", err.Error())
	}
	return fullPath, nil
}

func CreateDir(dirPath string) error {
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		errDir := os.MkdirAll(dirPath, 0755)
		if errDir != nil {
			return errDir
		}
		log.Printf("Directory created: %s\n", dirPath)
	} else {
		log.Printf("Directory already exists: %s\n", dirPath)
	}
	return nil
}

func WriteFile(fullPath string, content []string) error {
	file, err := os.Create(fullPath)
	if err != nil {
		return err
	}
	defer file.Close()

	for _, line := range content {
		_, err := file.WriteString(line + "\n")
		if err != nil {
			return err
		}
	}
	return nil
}

func SetFileAndDirPermsRecursive(nonRootUser, filePath string) error {

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return err
	}

	usr, err := user.Lookup(nonRootUser)
	if err != nil {
		log.Fatalf("Failed to look up user %q: %v", nonRootUser, err)
		return err
	}

	// Convert UID/GID to integers
	uid, err := strconv.Atoi(usr.Uid)
	if err != nil {
		log.Fatalf("Failed to convert UID (%s) to integer: %v", usr.Uid, err)
		return err
	}
	gid, err := strconv.Atoi(usr.Gid)
	if err != nil {
		log.Fatalf("Failed to convert GID (%s) to integer: %v", usr.Gid, err)
		return err
	}

	// Recursively walk the directory
	err = filepath.Walk(filePath, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		// Change ownership to the specified uid/gid.
		if err := os.Chown(path, uid, gid); err != nil {
			return err
		}

		err = os.Chmod(path, permissions)
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		log.Fatalf("Error walking the path %q: %v", filePath, err)
		return err
	}
	return nil
}
