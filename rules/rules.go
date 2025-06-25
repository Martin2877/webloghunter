package rules

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"io/ioutil"
	"regexp"

	apachelogparser "github.com/dsparling/go-apache-log-parser"
	"gopkg.in/yaml.v3"
)

type Detection struct {
	Rules     *Rules      `json:"rules"`
	Logger    *log.Logger `json:"-"`
	Histories []History   `json:"histories"`
	Attackers []Attacker  `json:"attackers"`
}

type History struct {
	Lines       apachelogparser.Line `json:"lines"`
	AttackRegex AttackRegex          `json:"attackRegex"`
}

type Attacker struct {
	IP string `json:"ip"`
}

type Rules struct {
	AttackRegex  []AttackRegex  `json:"attackregex"`
	ScannerRegex []ScannerRegex `json:"scannerregex"`
	Other        []Other        `json:"other"`
}

type Rule struct {
	TypeName string         `json:"typename"`
	Regex    string         `json:"regex"`
	Place    string         `json:"place"`
	RegIns   *regexp.Regexp `json:"-"` // Compiled regex pattern
}

type AttackRegex struct {
	Id          int            `yaml:"id"`
	Regex       string         `yaml:"regex"`
	Place       string         `yaml:"place"`
	RegexId     int            `yaml:"regexid"`
	TypeId      int            `yaml:"typeid"`
	TypeName    string         `yaml:"typename"`
	Level       int            `yaml:"level"`
	LevelDesc   string         `yaml:"leveldesc"`
	ActionId    int            `yaml:"actionid"`
	ActionDesc  string         `yaml:"actiondesc"`
	ActionLevel int            `yaml:"actionlevel"`
	SubType     string         `yaml:"subtype"`
	RegIns      *regexp.Regexp `json:"-"`
}

type ScannerRegex struct {
	Regex    string         `yaml:"regex"`
	RegexId  int            `yaml:"regexid"`
	TypeId   int            `yaml:"typeid"`
	TypeName string         `yaml:"typename"`
	RegIns   *regexp.Regexp `json:"-"`
}

type Other struct {
	Regex    string `yaml:"regex"`
	Place    string `yaml:"place"`
	TypeName string `yaml:"typename"`
	RegIns   *regexp.Regexp `json:"-"`
}

// CompileRegex compiles all regex patterns in the rules
func (r *Rules) CompileRegex() error {
	// Compile attack regex
	for i := range r.AttackRegex {
		if r.AttackRegex[i].Regex == "" {
			continue
		}
		compiled, err := regexp.Compile(r.AttackRegex[i].Regex)
		if err != nil {
			return fmt.Errorf("failed to compile attack regex %s: %v", r.AttackRegex[i].Regex, err)
		}
		r.AttackRegex[i].RegIns = compiled
	}

	// Compile scanner regex
	for i := range r.ScannerRegex {
		if r.ScannerRegex[i].Regex == "" {
			continue
		}
		compiled, err := regexp.Compile(r.ScannerRegex[i].Regex)
		if err != nil {
			return fmt.Errorf("failed to compile scanner regex %s: %v", r.ScannerRegex[i].Regex, err)
		}
		r.ScannerRegex[i].RegIns = compiled
	}

	// Compile other regex
	for i := range r.Other {
		if r.Other[i].Regex == "" {
			continue
		}
		compiled, err := regexp.Compile(r.Other[i].Regex)
		if err != nil {
			return fmt.Errorf("failed to compile other regex %s: %v", r.Other[i].Regex, err)
		}
		r.Other[i].RegIns = compiled
	}

	return nil
}

// LoadRules loads rules from a configuration file
func LoadRules(configFile string) (*Rules, error) {
	// Read the configuration file
	data, err := ioutil.ReadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	// Parse the YAML configuration
	var rules Rules
	if err := yaml.Unmarshal(data, &rules); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %v", err)
	}

	// Compile all regex patterns
	if err := rules.CompileRegex(); err != nil {
		return nil, fmt.Errorf("failed to compile regex patterns: %v", err)
	}

	return &rules, nil
}

// Init initializes the Detection with rules from the specified config file.
// If no config file is provided, it looks for "rules.default.yaml" in the executable's directory.
func (ins *Detection) Init(configPath ...string) error {
	// Set default config file if not provided
	configFile := "rules.default.yaml"
	if len(configPath) > 0 && configPath[0] != "" {
		configFile = configPath[0]
	} else {
		// Get the directory of the executable
		exePath, err := os.Executable()
		if err != nil {
			return fmt.Errorf("failed to get executable path: %v", err)
		}
		exeDir := filepath.Dir(exePath)
		configFile = filepath.Join(exeDir, configFile)
	}

	// Load rules from config file
	rules, err := LoadRules(configFile)
	if err != nil {
		return err
	}

	ins.Rules = rules
	if len(rules.Other) > 0 {
		log.Printf("Successfully loaded %d rules from %s\n", len(rules.Other), configFile)
	}

	return nil
}

// NewDetection creates a new Detection instance with a logger that writes to the specified file
func NewDetection(logFile string) (*Detection, error) {
	// Create or open the log file with sync on write
	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %v", err)
	}

	// Create a logger that writes to the file and flushes immediately
	logger := log.New(&syncWriter{file: f}, "", log.LstdFlags|log.Lshortfile)

	return &Detection{
		Logger: logger,
	}, nil
}

// syncWriter wraps a file to ensure writes are synced to disk
type syncWriter struct {
	file *os.File
}

func (w *syncWriter) Write(p []byte) (n int, err error) {
	n, err = w.file.Write(p)
	if err != nil {
		return n, err
	}
	// Sync the file to ensure the write is flushed to disk
	err = w.file.Sync()
	return n, err
}

func (ins *Detection) AttackDetect(line apachelogparser.Line) (bool, error) {
	for _, rule := range ins.Rules.AttackRegex {
		switch rule.Place {
		case "url":
			match := rule.RegIns.FindAllString(line.URL, -1)
			if len(match) > 0 {
				ins.Logger.Println("============================")
				ins.Logger.Printf("Detected attack in URL: %s\n", line.URL)
				ins.Logger.Printf("Rule: %s\n", rule.ActionDesc)
				ins.Logger.Printf("Full request: %s\n", line.String())
				return true, nil
			}
		case "useragent":
			match := rule.RegIns.FindAllString(line.UserAgent, -1)
			if len(match) > 0 {
				ins.Logger.Println("============================")
				ins.Logger.Printf("Detected attack in User-Agent: %s\n", line.UserAgent)
				ins.Logger.Printf("Rule: %s\n", rule.ActionDesc)
				ins.Logger.Printf("Full request: %s\n", line.String())
				return true, nil
			}
		}
	}
	return false, nil
}

func (ins *Detection) ScannerDetect(line apachelogparser.Line) (bool, error) {
	for _, rule := range ins.Rules.ScannerRegex {
		match := rule.RegIns.FindAllString(line.UserAgent, -1)
		if len(match) > 0 {
			ins.Logger.Println("============================")
			ins.Logger.Printf("Detected scanner in User-Agent: %s\n", line.UserAgent)
			ins.Logger.Printf("Rule: %s\n", rule.TypeName)
			ins.Logger.Printf("Full request: %s\n", line.String())
			return true, nil
		}
	}
	return false, nil
}

func (ins *Detection) OtherDetect(line apachelogparser.Line) (bool, error) {
	for _, rule := range ins.Rules.Other {
		switch rule.Place {
		case "url":
			match := rule.RegIns.FindAllString(line.URL, -1)
			if len(match) > 0 {
				ins.Logger.Println("============================")
				ins.Logger.Printf("URL: %s\n", line.URL)
				ins.Logger.Printf("Rule: %s\n", rule.TypeName)
				ins.Logger.Printf("Full request: %s\n", line.String())
				return true, nil
			}
		case "useragent":
			match := rule.RegIns.FindAllString(line.UserAgent, -1)
			if len(match) > 0 {
				ins.Logger.Println("============================")
				ins.Logger.Printf("User-Agent: %s\n", line.UserAgent)
				ins.Logger.Printf("Rule: %s\n", rule.TypeName)
				ins.Logger.Printf("Full request: %s\n", line.String())
				return true, nil
			}
		}
	}
	return false, nil
}
