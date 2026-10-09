//go:build esxi_cancel_tool

// Local qualification helper, compiled from the existing govmomi source module.
// Input stays on stdin; credentials stay in the child environment. Never print
// input, API responses, endpoint credentials or exception details.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/vmware/govmomi"
	"github.com/vmware/govmomi/object"
	"github.com/vmware/govmomi/vim25/mo"
	"github.com/vmware/govmomi/vim25/types"
)

type keyboardInput struct {
	Reference string `json:"reference"`
	UUID      string `json:"uuid"`
	Owner     string `json:"owner"`
}

func run() error {
	if len(os.Args) != 1 {
		return errors.New("input must use stdin")
	}
	raw, err := boundedInput()
	if err != nil || len(raw) > 32768 {
		return errors.New("invalid input size")
	}
	var input keyboardInput
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || input.Reference == "" || len(input.Reference) > 80 || input.UUID == "" || !strings.HasPrefix(input.Owner, "LOCAL-ESXI:") {
		return errors.New("invalid ownership input")
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("trailing input refused")
	}
	control := true
	events := []types.UsbScanCodeSpecKeyEvent{{UsbHidCode: 0x06<<16 | 7, Modifiers: &types.UsbScanCodeSpecModifierType{LeftControl: &control}}}
	endpoint, err := url.Parse(os.Getenv("GOVC_URL"))
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil {
		return errors.New("invalid endpoint")
	}
	user, pass := os.Getenv("GOVC_USERNAME"), os.Getenv("GOVC_PASSWORD")
	if user == "" || pass == "" {
		return errors.New("missing credentials")
	}
	endpoint.User = url.UserPassword(user, pass)
	if endpoint.Path == "" || endpoint.Path == "/" {
		endpoint.Path = "/sdk"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	client, err := govmomi.NewClient(ctx, endpoint, os.Getenv("GOVC_INSECURE") == "true")
	if err != nil {
		return err
	}
	defer func() {
		logout, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		_ = client.Logout(logout)
	}()
	vm := object.NewVirtualMachine(client.Client, types.ManagedObjectReference{Type: "VirtualMachine", Value: input.Reference})
	var observed mo.VirtualMachine
	if err := vm.Properties(ctx, vm.Reference(), []string{"config.uuid", "config.annotation", "runtime.powerState"}, &observed); err != nil {
		return err
	}
	if observed.Config == nil || observed.Config.Uuid != input.UUID || observed.Config.Annotation != input.Owner || observed.Runtime.PowerState != types.VirtualMachinePowerStatePoweredOn {
		return errors.New("ownership mismatch")
	}
	_, err = vm.PutUsbScanCodes(ctx, types.UsbScanCodeSpec{KeyEvents: events})
	return err
}

func boundedInput() ([]byte, error) {
	type result struct {
		data []byte
		err  error
	}
	ready := make(chan result, 1)
	go func() { data, err := io.ReadAll(io.LimitReader(os.Stdin, 32769)); ready <- result{data, err} }()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case value := <-ready:
		return value.data, value.err
	case <-timer.C:
		return nil, errors.New("input deadline exceeded")
	}
}

func main() {
	if run() != nil {
		fmt.Fprintln(os.Stderr, "Private cancellation refused or failed; do not retry.")
		os.Exit(1)
	}
}
