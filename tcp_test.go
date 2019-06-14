// +build linux

package tcpraw

import "testing"

func TestDial(t *testing.T) {
	conn, err := Dial("tcp", "192.168.2.12:22")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(conn)
}
