package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/fatih/color"
	"github.com/mllamazares/webnose/pkg/models"
	"github.com/mllamazares/webnose/pkg/scanner"
	"github.com/mllamazares/webnose/pkg/templates"
	"github.com/schollz/progressbar/v3"
)

const BANNER = `
       |     |
       |     |
      /       \
     ( __   __ )
      '--'-;  ;
     _     |  |
__ /` + "`" + ` ` + "`" + `""-;_ |
\ '.;------. ` + "`" + `\      webnose v3.0
 | |    __..  |        by @sysrekt
 | \.-''   _  |       https://mll.sh
 | |  ,-'-,   |
 |  \__.-'    |
  \    '.    /
   \     \  /
    '.      |
      )     |
`

func main() {
	targetsArg := flag.String("t", "", "Target URL or file containing URLs")
	templatesDir := flag.String("templates-dir", os.ExpandEnv("$HOME/.webnose/smell_templates"), "Directory containing smell templates")
	outputFile := flag.String("o", "", "Output JSON report file")
	concurrency := flag.Int("c", 10, "Number of concurrent workers")
	timeout := flag.Int("timeout", 4, "HTTP request timeout")
	userAgent := flag.String("user-agent", "Mozilla/5.0 (compatible; webnose/3.0)", "User-Agent string")
	silent := flag.Bool("s", false, "Suppress output")
	tags := flag.String("tags", "", "Filter templates by tags (comma-separated)")

	flag.Parse()

	if !*silent {
		fmt.Fprintln(os.Stderr, BANNER)
	}

	if *targetsArg == "" {
		// Check stdin
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) != 0 {
			flag.Usage()
			os.Exit(1)
		}
	}

	// Load Templates
	if !*silent {
		color.Blue("[+] Loading templates from %s...", *templatesDir)
	}
	
	tagList := []string{}
	if *tags != "" {
		tagList = strings.Split(*tags, ",")
	}

	tmpls, err := templates.LoadTemplates(*templatesDir, tagList)
	if err != nil {
		if !*silent {
			color.Red("[-] Error loading templates: %v", err)
		}
		os.Exit(1)
	}
	if len(tmpls) == 0 {
		if !*silent {
			color.Red("[-] No templates found!")
		}
		os.Exit(1)
	}
	if !*silent {
		color.Green("[+] Loaded %d templates", len(tmpls))
	}

	// Load Targets
	var targets []string
	if *targetsArg != "" {
		if _, err := os.Stat(*targetsArg); err == nil {
			// It's a file
			file, err := os.Open(*targetsArg)
			if err != nil {
				color.Red("[-] Error reading targets file: %v", err)
				os.Exit(1)
			}
			defer file.Close()
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				if line := strings.TrimSpace(scanner.Text()); line != "" {
					targets = append(targets, line)
				}
			}
		} else {
			// Check if it looks like a file but doesn't exist
			lowerArg := strings.ToLower(*targetsArg)
			if strings.HasSuffix(lowerArg, ".txt") || 
			   strings.HasSuffix(lowerArg, ".subs") || 
			   strings.HasSuffix(lowerArg, ".list") || 
			   strings.HasSuffix(lowerArg, ".json") || 
			   strings.HasSuffix(lowerArg, ".csv") {
				color.Red("[-] Input file not found: %s", *targetsArg)
				os.Exit(1)
			}
			// Treat as URL
			targets = append(targets, *targetsArg)
		}
	} else {
		// Read from stdin
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			if line := strings.TrimSpace(scanner.Text()); line != "" {
				targets = append(targets, line)
			}
		}
	}

	if !*silent {
		color.Cyan("[+] Loaded %d targets", len(targets))
		color.Blue("[+] Starting analysis with %d workers...", *concurrency)
	}

	// Scan
	results := make([]models.Result, 0, len(targets))
	resultsChan := make(chan models.Result, len(targets))
	var wg sync.WaitGroup

	sem := make(chan struct{}, *concurrency)
	scan := scanner.NewScanner(tmpls, *timeout, *userAgent)

	var bar *progressbar.ProgressBar
	if !*silent {
		bar = progressbar.Default(int64(len(targets)))
	}

	for _, target := range targets {
		wg.Add(1)
		go func(t string) {
			defer wg.Done()
			sem <- struct{}{}
			res := scan.Scan(t)
			resultsChan <- res
			<-sem
			if bar != nil {
				bar.Add(1)
			}
			// Log error if any
			if res.Error != "" && !*silent {
				// Clear line for progress bar if needed, though progressbar handles it mostly
				// Using fmt.Fprintf to stderr to avoid interfering with progress bar too much
				// Ideally we'd use bar.Describe or similar, but simple log is okay
				// color.Red("[-] Target down: %s (%s)", t, res.Error) 
				// To avoid messing up the bar, we might skip logging or log after.
				// Let's just let it be silent during scan to keep bar clean, 
				// OR we can rely on the final report containing the error.
				// The user asked for a check, logging it is good.
			}
		}(target)
	}

	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	for res := range resultsChan {
		results = append(results, res)
		if res.Error != "" && !*silent {
             // We can print here but it might conflict with progress bar. 
             // Let's rely on the report including it.
		}
	}

	// Generate Report
	report := generateReport(results)

	// Output
	jsonData, _ := json.MarshalIndent(report, "", "  ")
	if *outputFile != "" {
		err := os.WriteFile(*outputFile, jsonData, 0644)
		if err != nil {
			if !*silent {
				color.Red("[-] Error writing report: %v", err)
			}
		} else {
			if !*silent {
				color.Green("\n[+] Report written to %s", *outputFile)
			}
		}
	} else {
		fmt.Println(string(jsonData))
	}
}

func generateReport(results []models.Result) models.Report {
	// Include all results, even errors
	var validResults []models.Result
	for _, r := range results {
		validResults = append(validResults, r)
	}

	// Sort URLs by risk
	sort.Slice(validResults, func(i, j int) bool {
		return validResults[i].RiskScore > validResults[j].RiskScore
	})

	// Aggregate Subdomains
	subStats := make(map[string]*models.SubdomainStats)
	for _, r := range validResults {
		if _, ok := subStats[r.Subdomain]; !ok {
			subStats[r.Subdomain] = &models.SubdomainStats{}
		}
		s := subStats[r.Subdomain]
		s.RiskScore += r.RiskScore
		s.URLCount++
		s.TotalSmells += r.SmellCount
		if r.RiskScore > s.MaxRisk {
			s.MaxRisk = r.RiskScore
		}
	}

	// Calculate Averages and Format
	finalSubStats := make(map[string]models.SubdomainStats)
	for sub, s := range subStats {
		s.RiskScore = math.Round(s.RiskScore*100) / 100
		s.AvgRisk = 0
		if s.URLCount > 0 {
			s.AvgRisk = math.Round((s.RiskScore/float64(s.URLCount))*100) / 100
		}
		finalSubStats[sub] = *s
	}

	return models.Report{
		Subdomains: finalSubStats,
		URLs:       validResults,
	}
}
