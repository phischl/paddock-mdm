// Command cmd runs the acceptance SMTP sink standalone on the development host and prints every message it receives,
// for the manual check of the e-mail transport: go run ./internal/sink/cmd [-addr :2525].
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"time"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/sink"
)

func main() {
	addr := flag.String("addr", ":"+strconv.Itoa(sink.SMTPPort()), "listen address")
	flag.Parse()
	s, err := sink.ListenSMTP(*addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer s.Close()
	fmt.Printf("smtp sink listening on %s\n", s.Addr())
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	printed := 0
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		mails := s.Mails()
		for _, m := range mails[printed:] {
			fmt.Printf("=== %s from %s to %v\n%s\n", m.Received.Format(time.RFC3339), m.From, m.To, m.Data)
		}
		printed = len(mails)
	}
}
