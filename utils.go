package main

import (
	"os"
	"path/filepath"
)

func loadFile(fileName string) string {
	data, err := embedFS.ReadFile(fileName)
	if err != nil {
		panic(err)
	}

	return string(data)
}

func createFile(fileName string) error {
	dirPath := filepath.Dir(fileName)
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		if err := os.MkdirAll(dirPath, 0755); err != nil {
			return err
		}

		file, err := os.Create(fileName)
		if err != nil {
			return err
		}
		file.Close()
		return nil
	}

	return nil
}
