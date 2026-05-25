//go:build !windows

package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"syscall"
)

func runBackground(args []string) {
	null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		log.Fatalf("Failed to open devnull: %v", err)
	}
	cmd := exec.Command(os.Args[0], args...)
	cmd.Stdin = null
	cmd.Stdout = null
	cmd.Stderr = null
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		log.Fatalf("Failed to start background process: %v", err)
	}
	fmt.Printf("[*] Agent running in background (PID %d)\n", cmd.Process.Pid)
	os.Exit(0)
}
