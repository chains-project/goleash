package main

import (
	"flag"
	"fmt"
	"math"
	"time"

	"github.com/chains-project/goleash/examples/example_restrict/dependencyA"
	"github.com/chains-project/goleash/examples/example_restrict/dependencyB"
	"github.com/chains-project/goleash/examples/example_restrict/dependencyC"
	_ "github.com/chains-project/goleash/goleash"
)

const runs = 10000

func runMain() {
	fmt.Println("\nCalling dependencyA (invoke FILES and NETWORK)")
	dependencyA.CallPDF()

	fmt.Println("\nCalling dependencyB (invoke FILES)")
	dependencyB.CallPDF()

	fmt.Println("\nCalling dependencyC (invoke NETWORK)")
	dependencyC.CallPDF()
}

func benchmark() []time.Duration {
	times := make([]time.Duration, runs)
	for i := 0; i < runs; i++ {
		start := time.Now()
		runMain()
		times[i] = time.Since(start)
	}
	return times
}

func calculateStats(times []time.Duration) (mean, stdDev time.Duration) {
	var sum, sumSquares float64
	for _, t := range times {
		seconds := t.Seconds()
		sum += seconds
		sumSquares += seconds * seconds
	}
	n := float64(len(times))
	meanSeconds := sum / n
	varianceSeconds := (sumSquares / n) - (meanSeconds * meanSeconds)
	stdDevSeconds := math.Sqrt(varianceSeconds)

	return time.Duration(meanSeconds * float64(time.Second)),
		time.Duration(stdDevSeconds * float64(time.Second))
}

func main() {
	benchmarkFlag := flag.Bool("benchmark", false, "Run benchmark")
	flag.Parse()

	if *benchmarkFlag {
		fmt.Println("Starting benchmark...")
		times := benchmark()
		mean, stdDev := calculateStats(times)

		fmt.Printf("Mean execution time: %v\n", mean)
		fmt.Printf("Standard deviation: %v\n", stdDev)
	} else {
		runMain()
	}
}
