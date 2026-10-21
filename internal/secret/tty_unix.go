//go:build !windows

package secret

func ttyPath() string { return "/dev/tty" }
