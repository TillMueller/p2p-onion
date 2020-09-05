package main

import (
	"bufio"
	"fmt"
	"io"
	"onion/config"
	"onion/logger"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"
)
import "onion/testing_setup"

var killPeers = false

func runAndPrintCommand(cmd string, wg *sync.WaitGroup, t *testing.T) {
	wg.Add(1)
	prog := exec.Command("bash", "-c", cmd)
	prog.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	outPipe, err := prog.StdoutPipe()
	if err != nil {
		t.Errorf("Could not set stdout pipe for " + cmd)
	}
	errPipe, err := prog.StderrPipe()
	if err != nil {
		t.Errorf("Could not set stderr pipe for " + cmd)
	}
	scanner := bufio.NewScanner(io.MultiReader(outPipe, errPipe))
	err = prog.Start()
	if err != nil {
		t.Errorf("Could not start process " + cmd)
		return
	}
	go func() {
		for scanner.Scan() {
			fmt.Println("[" + cmd + "] " + scanner.Text())
		}
	}()
	for {
		time.Sleep(100 * time.Millisecond)
		if killPeers {
			t.Log("Killing process " + cmd)
			pgid, err := syscall.Getpgid(prog.Process.Pid)
			if err != nil {
				t.Log("Could not kill process " + cmd)
				return
			}
			_ = syscall.Kill(-pgid, syscall.SIGTERM)
			wg.Done()
		}
	}
}

func removeLogFile(n int, t *testing.T) {
	err := os.Remove("testing_setup/peer" + strconv.Itoa(n) + "/onion.log")
	if err != nil {
		t.Errorf("Could not remove log file for peer " + strconv.Itoa(n))
		return
	}
}

func cleanupAndExit(wg *sync.WaitGroup) {
	killPeers = true
	wg.Wait()
}

func initializeTest(wg *sync.WaitGroup, t *testing.T) {
	// remove testing log file
	err := os.Remove("testing.log")
	if err != nil {
		t.Errorf("Could not remove testing logfile (testing.log)")
	}
	// remove log files and start peers in separate instances
	for i := 0; i < 5; i++ {
		removeLogFile(i, t)
		go runAndPrintCommand("go run main.go -c testing_setup/peer"+strconv.Itoa(i)+"/config.ini", wg, t)
	}
	config.LogfileLocation = "testing.log"
	// start our logger
	logger.Initialize()
	// start mocked RPS module
	go testing_setup.InitializeRPS(t)
	// let them start up
	time.Sleep(3 * time.Second)
}

func TestBuildTunnel(t *testing.T) {
	var wg sync.WaitGroup

	initializeTest(&wg, t)
	defer cleanupAndExit(&wg)
	// start client on initiator side
	go testing_setup.InitializeClient("localhost:65510")
	// start client on receiver side
	go testing_setup.InitializeClient("localhost:65514")
	// start client somewhere in the middle (no data should arrive there)
	go testing_setup.InitializeClient("localhost:65512")
	// let them start up
	time.Sleep(time.Second)
	// send build tunnel command
	testing_setup.BuildTunnelTest("localhost:65510")
	time.Sleep(20 * time.Second)
}

func TestCoverTraffic(t *testing.T) {
	var wg sync.WaitGroup
	defer cleanupAndExit(&wg)
	initializeTest(&wg, t)
	// start client on initiator side
	go testing_setup.InitializeClient("localhost:65510")
	// start client on receiver side
	go testing_setup.InitializeClient("localhost:65514")
	// let them start up
	time.Sleep(time.Second)
	// send cover command
	testing_setup.CoverTrafficTest("localhost:65510")
	time.Sleep(30 * time.Second)
}