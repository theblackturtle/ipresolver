package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/OWASP/Amass/v3/resolvers"
)

var (
	inputFile     string
	threads       int
	resolverFile  string
	ResolversList []string
)

func main() {
	flag.StringVar(&inputFile, "i", "", "Subdomains list")
	flag.IntVar(&threads, "t", 5, "Threads to run")
	flag.StringVar(&resolverFile, "r", "", "Resolver file (Format: ip:port)")
	flag.Parse()

	if inputFile == "" {
		fmt.Println("Please check your input file.")
		os.Exit(0)
	}

	if resolverFile != "" {
		rf, err := os.Open(resolverFile)
		if err != nil {
			panic(err)
		}
		rs := bufio.NewScanner(rf)
		for rs.Scan() {
			ResolversList = append(ResolversList, rs.Text())
		}
	} else {
		ResolversList = []string{
			"1.1.1.1:53",     // Cloudflare
			"8.8.8.8:53",     // Google
			"64.6.64.6:53",   // Verisign
			"77.88.8.8:53",   // Yandex.DNS
			"74.82.42.42:53", // Hurricane Electric
			"1.0.0.1:53",     // Cloudflare Secondary
			"8.8.4.4:53",     // Google Secondary
			"77.88.8.1:53",   // Yandex.DNS Secondary
		}
	}
	f, err := os.Open(inputFile)
	if err != nil {
		panic(err)
	}

	pool := resolvers.SetupResolverPool(ResolversList, false, false, nil)
	if pool == nil {
		fmt.Println("Failed to init pool")
		os.Exit(0)
	}

	var wg sync.WaitGroup
	jobChan := make(chan string, threads*2)
	ctx := context.Background()
	defer ctx.Done()

	var unsortIPList []string
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for domain := range jobChan {
				if a, _, err := pool.Resolve(ctx, domain, "A", resolvers.PriorityHigh); err == nil {
					if a != nil && len(a) > 0 {
						for _, e := range a {
							unsortIPList = append(unsortIPList, e.Data)
						}
					}
				}
			}
		}()
	}

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		jobChan <- strings.ToLower(sc.Text())
	}
	close(jobChan)
	wg.Wait()
	for _, ip := range removeDuplicated(unsortIPList) {
		netIP := net.ParseIP(ip)
		if netIP.IsGlobalUnicast() {
			fmt.Println(netIP.String())
		}
	}
}

func removeDuplicated(ips []string) []string {
	seen := make(map[string]bool)
	uniqList := []string{}
	for _, ip := range ips {
		if _, ok := seen[ip]; !ok {
			seen[ip] = true
			uniqList = append(uniqList, ip)
		} else {
			continue
		}
	}
	return uniqList
}
