// +build linux

package tcpraw

import "testing"

func TestDial(t *testing.T) {
	conn, err := Dial("tcp", "127.0.0.1:22")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(conn)

	buf := make([]byte, 1500)
	n, addr, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(n, addr)
	t.Log(buf[:n])
}
