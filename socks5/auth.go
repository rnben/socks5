package socks5

import (
	"errors"
	"fmt"
	"io"
)

const Socks5Version uint8 = 5
const CmdConnect uint8 = 1
const UserAuthVersion uint8 = 1
const NoAuth uint8 = 0
const UserPassAuth uint8 = 2
const authSuccess uint8 = 0
const authFailure uint8 = 1

type Authenticator interface {
	Authenticate(reader io.Reader, writer io.Writer) error
}

type NoAuthAuthenticator struct{}

func (a NoAuthAuthenticator) Authenticate(reader io.Reader, writer io.Writer) error {
	_, err := writer.Write([]byte{Socks5Version, NoAuth})
	return err
}

type UserPassAuthenticator struct {
	Credentials CredentialStore
}

func (a UserPassAuthenticator) Authenticate(reader io.Reader, writer io.Writer) error {
	buf := make([]byte, 256)

	// Read the version byte
	n, err := io.ReadFull(reader, buf[:2])
	if n != 2 {
		return errors.New("reading header: " + err.Error())
	}

	ver, nMethods := buf[0], int(buf[1])
	if ver != Socks5Version {
		return errors.New("invalid version")
	}

	// Get the methods
	n, err = io.ReadFull(reader, buf[:nMethods])
	if n != nMethods {
		return errors.New("reading methods: " + err.Error())
	}

	// Tell the client to use user/pass auth
	if _, err := writer.Write([]byte{Socks5Version, UserPassAuth}); err != nil {
		return err
	}

	// Get the version and username length
	header := []byte{0, 0}
	if _, err := io.ReadAtLeast(reader, header, 2); err != nil {
		return err
	}

	// Ensure we are compatible
	if header[0] != UserAuthVersion {
		return fmt.Errorf("Unsupported auth version: %v", header[0])
	}

	// Get the user name
	userLen := int(header[1])
	user := make([]byte, userLen)
	if _, err := io.ReadAtLeast(reader, user, userLen); err != nil {
		return err
	}

	// Get the password length
	if _, err := reader.Read(header[:1]); err != nil {
		return err
	}

	// Get the password
	passLen := int(header[0])
	pass := make([]byte, passLen)
	if _, err := io.ReadAtLeast(reader, pass, passLen); err != nil {
		return err
	}

	// Verify the password
	if a.Credentials.Valid(string(user), string(pass)) {
		if _, err := writer.Write([]byte{UserAuthVersion, authSuccess}); err != nil {
			return err
		}
	} else {
		if _, err := writer.Write([]byte{UserAuthVersion, authFailure}); err != nil {
			return err
		}
		return errors.New("user auth failed")
	}

	// Done
	return nil
}
