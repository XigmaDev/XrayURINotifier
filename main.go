package main

import (
	"fmt"

	"github.com/go-telegram/bot/models"
)

const (
	BotTokenEnvKey      = "BOT_TOKEN"
	BotHTTPProxyURL     = "BOT_PROXY_URL"
	ParseModeMarkdownV1 = models.ParseMode("Markdown")
)

var (
	AppName        = ""
	AppVersion     = ""
	AppCompileTime = ""
)

func main() {
	//compileTime, err := time.Parse(time.RFC3339, AppCompileTime)
	// if nil != err {
	// 	panic(err)
	// }

	// log := zerolog.New(zerolog.NewConsoleWriter(func(w *zerolog.ConsoleWriter) { w.Out = os.Stderr; w.TimeFormat = time.RFC3339 })).With().Timestamp().Logger().Level(zerolog.TraceLevel)
	// buildBot(log)

	host := "127.0.0.1"
	port := 10809
	socksport := 10808
	tport := 1234
	uri := "vless://005c1ede-6660-423b-88db-730cda1e2ea3@skipped-litigate.1siren.ir:3799?type=tcp&path=%2F&host=varzesh3.com&headerType=http&security=none#khodemon%7Ckhodam"

	filePath := convertURIToJSON(host, port, socksport, tport, uri)
	// latency := urlTest()
	// fmt.Printf("Latency: %d ms\n", latency)
	fmt.Printf(filePath)
}
