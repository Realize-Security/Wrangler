package files

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path"
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

// WriteSliceToFile returns a full path to a newly created file
func WriteSliceToFile(directory, filename string, targets []string) (string, error) {
	err := CreateDir(directory)
	if err != nil {
		return "", fmt.Errorf("unable to create directory: %s", err.Error())
	}

	p := path.Join(directory, filename)
	err = WriteFile(p, targets)
	if err != nil {
		return "", fmt.Errorf("unable to create file: %s", err.Error())
	}
	return p, nil
}

func CreateDir(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		errDir := os.MkdirAll(path, 0755)
		if errDir != nil {
			return errDir
		}
		log.Printf("Directory created: %s\n", path)
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
		_, err = file.WriteString(line + "\n")
		if err != nil {
			return err
		}
	}
	return nil
}

func MakeTempDir(base, dir string) (string, error) {
	d, err := os.MkdirTemp(base, dir)
	if err != nil {
		return "", err
	}
	return d, nil
}
