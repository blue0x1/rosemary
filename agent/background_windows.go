// Rosemary - Cross-platform transparent tunneling platform
// Copyright (C) 2026 Chokri Hammedi (blue0x1)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, version 3 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//go:build windows

package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

func runBackground(args []string) {
	 
	psArgs := []string{"Start-Process", "-FilePath", os.Args[0], "-WindowStyle", "Hidden"}
	if len(args) > 0 {
		quoted := make([]string, len(args))
		for i, a := range args {
			quoted[i] = `"` + strings.ReplaceAll(a, `"`, `\"`) + `"`
		}
		psArgs = append(psArgs, "-ArgumentList", strings.Join(quoted, ","))
	}
	cmd := exec.Command("powershell", psArgs...)
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Run(); err != nil {
		log.Fatalf("Failed to start background process: %v", err)
	}
	fmt.Println("[*] Agent started in background")
	os.Exit(0)
}
