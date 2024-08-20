package tcpraw

import (
	"os"
	"os/signal"
	"syscall"
)

func init() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	<-sigCh
}
