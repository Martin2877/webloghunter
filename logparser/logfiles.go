package logparser

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
)

func visit(files *[]string) filepath.WalkFunc {
	return func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Fatal(err)
		}
		*files = append(*files, path)
		return nil
	}
}

func GetFiles(path string) ([]string, error) {
	var files []string
	err := filepath.Walk(path, visit(&files))
	if err != nil {
		return nil, err
	}
	return files, nil
}

// 判断所给路径是否为文件夹

func IsDir(path string) bool {
	s, err := os.Stat(path)
	if err != nil {

		return false
	}
	return s.IsDir()
}

type LogFiles struct {
	Files    []string `json:"files"`
	AllLines [][]Line `json:"all_lines"`
}

func (lf *LogFiles) Load(path string) error {
	if IsDir(path) {
		files, err := GetFiles(path)
		if err != nil {
			return err
		}
		for _, file := range files {
			// Skip directories and only add regular files
			if !IsDir(file) {
				lf.Files = append(lf.Files, file)
			}
		}
		// If no files were found in the directory, return an error
		if len(lf.Files) == 0 {
			return fmt.Errorf("no log files found in directory: %s", path)
		}
	} else {
		// It's a file, add it directly
		lf.Files = append(lf.Files, path)
	}
	return nil
}

func (lf *LogFiles) Parse(file string) ([]Line, error) {
	lines, err := Parse(file)
	if err != nil {
		return nil, err
	}
	return lines, nil
}
