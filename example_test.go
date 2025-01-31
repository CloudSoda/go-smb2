package smb2_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"testing"

	"github.com/cloudsoda/go-smb2"
	"github.com/stretchr/testify/require"
)

func Example() {
	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     "Guest",
			Password: "",
			Domain:   "MicrosoftAccount",
		},
	}

	c, err := d.Dial(context.Background(), "localhost:445")
	if err != nil {
		panic(err)
	}
	defer func() {
		_ = c.Logoff()
	}()

	fs, err := c.Mount(`\\localhost\share`)
	if err != nil {
		panic(err)
	}
	defer func() {
		_ = fs.Umount()
	}()

	f, err := fs.Create("hello.txt")
	if err != nil {
		panic(err)
	}
	defer func() {
		f.Close()
		_ = fs.Remove("hello.txt")
	}()

	_, err = f.Write([]byte("Hello world!"))
	if err != nil {
		panic(err)
	}

	_, err = f.Seek(0, io.SeekStart)
	if err != nil {
		panic(err)
	}

	bs, err := io.ReadAll(f)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(bs))

	// Hello world!
}

// This test is temporal, I will remove it later
// it is for exploring the capabilities of go-smb2 package and for extracting information from a real SMB share
// TODO: remove this test once security info can be extracted/set using compound requests
func TestExample(t *testing.T) {
	t.Parallel()

	user := "fru"
	domain := "DESKTOP-MT6FUDC"
	address := "192.168.56.102:445"

	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     user,
			Password: "armia krajowa",
			Domain:   domain,
		},
	}

	// TODO: find if it is already documented that the port must be explicitly set, if not, then document it
	c, err := d.Dial(context.Background(), address) // port must be part of the address
	require.NoError(t, err)
	defer func() { _ = c.Logoff() }()

	fs, err := c.Mount(`\\192.168.56.102\Public`) // should I use the domain instead?
	// fs, err := c.Mount(`\\DESKTOP-MT6FUDC\Public`) // should I use the domain instead?
	require.NoError(t, err)
	defer func() { _ = fs.Umount() }()

	// list files under Public share

	// infos, err := fs.ReadDir("")
	// require.NoError(t, err)

	// // produce a string with the files and some additional information, just for debugging and to verify if this works
	// sb := &strings.Builder{}
	// sb.WriteString(fmt.Sprintf("server: %s\ndomain: %s\nshare: %s\nfiles: %d\n", address, domain, "Public", len(infos)))
	// for _, info := range infos {
	// 	sb.WriteString(fmt.Sprintf("\t- '%s'\n", info.Name()))
	// }

	// fmt.Println("---")
	// fmt.Println(sb.String())
	// fmt.Println("---")

	// try to get secuyrity info

	secFlags := smb2.OwnerSecurityInformation | smb2.GroupSecurityInformation | smb2.DACLSecurityInformation | smb2.SACLSecurityInformation

	// info, err := fs.SecurityInfoRaw("hello.txt", secFlags)
	// require.NoError(t, err)

	// info64 := base64.StdEncoding.EncodeToString(info)

	// fmt.Println("---")
	// fmt.Println("hello.txt binary security descriptor")
	// fmt.Println("---")
	// fmt.Println(info64)
	// fmt.Println("---")

	// // try to get parsed security descriptor
	// sd, err := fs.SecurityInfo("hello.txt", secFlags)
	// require.NoError(t, err, "while getting parsed security descriptor")

	// fmt.Println("---")
	// fmt.Println("hello.txt security descriptor")
	// fmt.Println("---")
	// fmt.Println(sd.StringIndent(0))
	// fmt.Println("---")

	// // setting security attributes to a second file named `good-bye.txt`
	// err = fs.SetSecurityInfo("good-bye.txt", secFlags, sd)
	// require.NoError(t, err)

	// try to get security info using a single call
	info2, err := fs.SecurityInfoRaw2("hello.txt", secFlags)
	require.NoError(t, err)
	info2_64 := base64.StdEncoding.EncodeToString(info2)

	fmt.Println("---")
	fmt.Println("hello.txt binary security descriptor (single call)")
	fmt.Println("---")
	fmt.Println(info2_64)
	fmt.Println("---")

	// Fail on purpose to see the output
	require.Failf(t, "FAILED ON PURPOSE SO YOU CAN REVIEW OUTPUT:\n>> sec info extracted for hello.txt", "\n%s\n", info2_64)
}
