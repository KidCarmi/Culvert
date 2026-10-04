//go:build esxi_keyboard_tool

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
	Text      string `json:"text"`
	Code      string `json:"code"`
}

func key(code int32, shift bool) types.UsbScanCodeSpecKeyEvent {
	return types.UsbScanCodeSpecKeyEvent{UsbHidCode: code<<16 | 7,
		Modifiers: &types.UsbScanCodeSpecModifierType{LeftShift: &shift}}
}

func keys(input keyboardInput) ([]types.UsbScanCodeSpecKeyEvent, error) {
	if (input.Text == "") == (input.Code == "") || len(input.Text) > 4096 {
		return nil, errors.New("invalid keyboard input")
	}
	if input.Code != "" {
		codes := map[string]int32{"KEY_ENTER": 0x28, "KEY_F2": 0x3b, "KEY_0": 0x27, "KEY_1": 0x1e, "KEY_2": 0x1f, "KEY_3": 0x20, "KEY_4": 0x21, "KEY_Q": 0x14, "KEY_B": 0x05, "KEY_CTRL_L": 0x0f}
		code, ok := codes[input.Code]
		if !ok {
			return nil, errors.New("key is not allowlisted")
		}
		event := key(code, false)
		if input.Code == "KEY_CTRL_L" {
			control := true
			event.Modifiers.LeftControl = &control
		}
		return []types.UsbScanCodeSpecKeyEvent{event}, nil
	}
	var result []types.UsbScanCodeSpecKeyEvent
	plain := "1234567890-= []\\;'`,./"
	shifted := "!@#$%^&*()_+ {}|:\"~<>?"
	codes := []int32{0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x2d, 0x2e, 0x2c, 0x2f, 0x30, 0x31, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38}
	for _, ch := range input.Text {
		switch {
		case ch >= 'a' && ch <= 'z':
			result = append(result, key(int32(ch-'a')+4, false))
		case ch >= 'A' && ch <= 'Z':
			result = append(result, key(int32(ch-'A')+4, true))
		default:
			index := strings.IndexRune(plain, ch)
			shift := false
			if index < 0 {
				index = strings.IndexRune(shifted, ch)
				shift = true
			}
			if index < 0 {
				return nil, errors.New("unsupported character")
			}
			result = append(result, key(codes[index], shift))
		}
	}
	return result, nil
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
	if json.Unmarshal(raw, &input) != nil || input.Reference == "" || len(input.Reference) > 80 || input.UUID == "" || !strings.HasPrefix(input.Owner, "LOCAL-ESXI:") {
		return errors.New("invalid ownership input")
	}
	events, err := keys(input)
	if err != nil {
		return err
	}
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
	if err := vm.Properties(ctx, vm.Reference(), []string{"config.uuid", "config.annotation"}, &observed); err != nil {
		return err
	}
	if observed.Config == nil || observed.Config.Uuid != input.UUID || observed.Config.Annotation != input.Owner {
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
		fmt.Fprintln(os.Stderr, "Private keyboard operation refused or failed; do not retry credential input.")
		os.Exit(1)
	}
}
