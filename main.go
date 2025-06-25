package main

import (
	"fmt"
	"log"
	"os"

	"github.com/Martin2877/webloghunter/logparser"
	"github.com/Martin2877/webloghunter/requester"
	"github.com/Martin2877/webloghunter/rules"
	apachelogparser "github.com/dsparling/go-apache-log-parser"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
)

var (
	logFile string
	rootCmd = &cobra.Command{
		Use:   "webloghunter",
		Short: "Web log hunter for HTTP attack analysis",
	}
)

func init() {
	// Initialize logging
	rootCmd.PersistentFlags().StringVarP(&logFile, "log", "l", "webloghunter.log", "Path to log file")
}

func setupLogging() {
	logFile, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	log.SetOutput(logFile)
}

func replayCmd() *cobra.Command {
	var (
		host string
		path string
	)

	cmd := &cobra.Command{
		Use:   "replay",
		Short: "Replay web logs to a target host",
		RunE: func(cmd *cobra.Command, args []string) error {
			setupLogging()
			return replayLogs(path, host)
		},
	}

	cmd.Flags().StringVarP(&path, "log", "l", ".", "Path to log file or directory (default is current directory)")
	cmd.Flags().StringVarP(&host, "target", "t", "http://localhost:8000", "Target host URL")
	cmd.MarkFlagRequired("target")

	return cmd
}

func detectionCmd() *cobra.Command {
	var (
		path   string
		config string
	)

	cmd := &cobra.Command{
		Use:   "detection",
		Short: "Detect attacks in web logs",
		RunE: func(cmd *cobra.Command, args []string) error {
			setupLogging()
			return detectionRun(cmd, args)
		},
	}

	cmd.Flags().StringVarP(&path, "log", "l", "", "Path to log file or directory")
	cmd.Flags().StringVarP(&config, "config", "c", "", "Path to config file (optional)")
	cmd.MarkFlagRequired("log")

	return cmd
}

func replayLogs(path, host string) error {
	log.Printf("Loading log files from: %s\n", path)
	lf := logparser.LogFiles{}
	if err := lf.Load(path); err != nil {
		return fmt.Errorf("failed to load log files: %v", err)
	}

	if len(lf.Files) == 0 {
		return fmt.Errorf("no log files found in: %s", path)
	}

	log.Printf("Found %d log files to process\n", len(lf.Files))
	requester := requester.Requester{Address: host}

	var totalRequests int
	for _, file := range lf.Files {
		log.Printf("Processing file: %s\n", file)
		lines, err := lf.Parse(file)
		if err != nil {
			log.Printf("Error parsing file %s: %v\n", file, err)
			continue
		}

		if len(lines) == 0 {
			log.Printf("No log entries found in file: %s\n", file)
			continue
		}

		log.Printf("Sending %d requests from %s\n", len(lines), file)
		if err := requester.LoadOne(lines); err != nil {
			log.Printf("Error preparing requests from %s: %v\n", file, err)
			continue
		}

		if err := requester.Send(); err != nil {
			log.Printf("Error sending requests from %s: %v\n", file, err)
			continue
		}
		totalRequests += len(lines)
	}

	if totalRequests == 0 {
		return fmt.Errorf("no valid log entries were processed from: %s", path)
	}

	log.Printf("Successfully processed %d requests from %d files\n", totalRequests, len(lf.Files))
	return nil
}

func detectionRun(cmd *cobra.Command, args []string) error {
	path, err := cmd.Flags().GetString("log")
	if err != nil {
		return err
	}
	configFile, err := cmd.Flags().GetString("config")
	if err != nil {
		return err
	}

	// Create detection log file path based on input log file
	logFile := path + ".detection.log"

	// Initialize detection with rules and logger
	dt, err := rules.NewDetection(logFile)
	if err != nil {
		return fmt.Errorf("failed to create detection logger: %v", err)
	}

	if err := dt.Init(configFile); err != nil {
		return fmt.Errorf("failed to initialize detection: %v", err)
	}

	log.Printf("Detection logs will be written to: %s\n", logFile)

	lf := logparser.LogFiles{}
	if err := lf.Load(path); err != nil {
		return fmt.Errorf("failed to load log files: %v", err)
	}

	for _, file := range lf.Files {
		if logparser.IsDir(file) {
			continue
		}

		log.Printf("Analyzing file: %s\n", file)
		lines, err := apachelogparser.Parse(file)
		if err != nil {
			log.Printf("Error parsing file %s: %v\n", file, err)
			continue
		}

		bar := progressbar.Default(int64(len(lines)))
		for _, line := range lines {
			bar.Add(1)
			if _, err := dt.AttackDetect(line); err != nil {
				log.Printf("Error in attack detection: %v\n", err)
			}
			if _, err := dt.ScannerDetect(line); err != nil {
				log.Printf("Error in scanner detection: %v\n", err)
			}
			if _, err := dt.OtherDetect(line); err != nil {
				log.Printf("Error in other detection: %v\n", err)
			}
		}
	}
	return nil
}

func main() {
	rootCmd.AddCommand(replayCmd())
	rootCmd.AddCommand(detectionCmd())

	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
