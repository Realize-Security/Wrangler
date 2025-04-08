package nmap

import (
	"Wrangler/pkg/models"
	"encoding/xml"
	"os"
)

// ReadNmapXML returns a pointer to models.NmapRun
func ReadNmapXML(nmapFile string) (*models.NmapRun, error) {
	f, err := os.Open(nmapFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var result models.NmapRun
	if err := xml.NewDecoder(f).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}
