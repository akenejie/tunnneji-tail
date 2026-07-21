// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package ipnauth controls access to the LocalAPI.
package ipnauth

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"runtime"
	"strconv"

	"tailscale.com/ipn"
	"tailscale.com/safesocket"
	"tailscale.com/types/logger"
	"tailscale.com/util/groupmember"
	"tailscale.com/version/distro"
)

// ErrNotImplemented is returned by ConnIdentity.WindowsToken when it is not
// implemented for the current GOOS.
var ErrNotImplemented = errors.New("not implemented for GOOS=" + runtime.GOOS)

// WindowsToken represents the current security context of a Windows user.
type WindowsToken interface {
	io.Closer
	EqualUIDs(other WindowsToken) bool
	IsAdministrator() (bool, error)
	IsUID(uid ipn.WindowsUserID) bool
	UID() (ipn.WindowsUserID, error)
	IsElevated() bool
	IsLocalSystem() bool
	UserDir(folderID string) (string, error)
	Username() (string, error)
}

// ConnIdentity represents the owner of a localhost TCP or unix socket connection
// connecting to the LocalAPI.
type ConnIdentity struct {
	conn       net.Conn
	notWindows bool
	isUnixSock bool
	creds      PeerCreds
}

func (ci *ConnIdentity) IsUnixSock() bool { return ci.isUnixSock }
func (ci *ConnIdentity) Creds() PeerCreds { return ci.creds }

// PeerCreds is the interface for a github.com/tailscale/peercred.Creds,
// if linked into the binary.
type PeerCreds interface {
	UserID() (uid string, ok bool)
	PID() (pid int, ok bool)
}

// LookupUserFromID is a wrapper around os/user.LookupId.
func LookupUserFromID(logf logger.Logf, uid string) (*user.User, error) {
	return user.LookupId(uid)
}

// IsReadonlyConn reports whether the connection should be considered read-only,
// meaning it's not allowed to change the state of the node.
//
// Read-only also means it's not allowed to access sensitive information, which
// admittedly doesn't follow from the name. Consider this "IsUnprivileged".
func (ci *ConnIdentity) IsReadonlyConn(operatorUID string, logf logger.Logf) bool {
	const ro = true
	const rw = false
	if !safesocket.PlatformUsesPeerCreds() {
		return rw
	}
	creds := ci.creds
	if creds == nil {
		logf("connection from unknown peer; read-only")
		return ro
	}
	uid, ok := creds.UserID()
	if !ok {
		logf("connection from peer with unknown userid; read-only")
		return ro
	}
	if uid == "0" {
		logf("connection from userid %v; root has access", uid)
		return rw
	}
	if selfUID := os.Getuid(); selfUID != 0 && uid == strconv.Itoa(selfUID) {
		logf("connection from userid %v; connection from non-root user matching daemon has access", uid)
		return rw
	}
	if operatorUID != "" && uid == operatorUID {
		logf("connection from userid %v; is configured operator", uid)
		return rw
	}
	if yes, err := isLocalAdmin(uid); err != nil {
		logf("connection from userid %v; read-only; %v", uid, err)
		return ro
	} else if yes {
		logf("connection from userid %v; is local admin, has access", uid)
		return rw
	}
	logf("connection from userid %v; read-only", uid)
	return ro
}

func isLocalAdmin(uid string) (bool, error) {
	u, err := user.LookupId(uid)
	if err != nil {
		return false, err
	}
	var adminGroup string
	switch {
	case runtime.GOOS == "darwin":
		adminGroup = "admin"
	case distro.Get() == distro.QNAP:
		adminGroup = "administrators"
	default:
		return false, fmt.Errorf("no system admin group found")
	}
	return groupmember.IsMemberOfGroup(adminGroup, u.Username)
}
