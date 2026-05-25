//go:build windows

package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

func runBackground(args []string) {
	exe, err := os.Executable()
	if err != nil {
		log.Fatalf("Failed to resolve executable path: %v", err)
	}
	exe, err = filepath.Abs(exe)
	if err != nil {
		log.Fatalf("Failed to get absolute path: %v", err)
	}
	cmd := exec.Command(exe, args...)
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000 | 0x00000200 | 0x01000000, // CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP | CREATE_BREAKAWAY_FROM_JOB
	}
	if err := cmd.Start(); err != nil {
		log.Fatalf("Failed to start background process: %v", err)
	}
	fmt.Printf("[*] Agent started in background (PID %d)\n", cmd.Process.Pid)
	os.Exit(0)
}
