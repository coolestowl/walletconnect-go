package main

import (
	"log/slog"

	walletconnectgo "github.com/coolestowl/walletconnect-go"
	"github.com/samber/lo"
)

func main() {
	slog.SetLogLoggerLevel(slog.LevelInfo)

	wcStr := "wc:<paring_topic>@2?relay-protocol=irn&symKey=<symKey>"

	c := new(walletconnectgo.Core)
	c.ProjectId = "<project_id>"
	// c.SetProxy("127.0.0.1:1080")

	lo.Must0(c.Pair(wcStr))
	select {}
}
