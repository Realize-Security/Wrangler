package files

import (
	"bufio"
	"fmt"
	"os"
)

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
