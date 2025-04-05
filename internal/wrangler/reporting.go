package wrangler

import (
	"Wrangler/internal/files"
	"Wrangler/pkg/helpers"
	"log"
	"os"
	"path"
)

func (wr *wranglerRepository) CreateReportDirectory(dir, projectName string) (string, error) {
	var report string
	if dir != "" {
		wd, err := os.Getwd()
		if err != nil {
			log.Fatal(err)
		}
		report = path.Join(wd, dir, helpers.SpacesToUnderscores(projectName))

		_, err = os.Stat(report)
		if err != nil {
			err = files.CreateDir(report)
			if err != nil {
				return "", err
			}
		}
	}
	return report, nil
}
