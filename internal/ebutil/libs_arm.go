//go:build arm

package ebutil

// This constant is for 64-bit systems. 32-bit ARM is not supported.
// If ever it becomes supported, it should be handled with a `usrLib32MultiarchDir` constant.
const usrLibMultiarchDir = "/var/empty"
