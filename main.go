package main

import (
	"encoding/gob"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/joho/godotenv"
	"github.com/rs/zerolog"
	tgbotapi "gopkg.in/telegram-bot-api.v4"
)

const (
	ChannelIDsEnvKeys = "CHANNEL_IDS"
	ChatIDEnvKey      = "CHAT_ID"
	BotTokenEnvKey    = "BOT_TOKEN"
	BotHTTPProxyURL   = "BOT_PROXY_URL"
)

var re = regexp.MustCompile(`(vmess://|vless://|trojan://|ss://)[^\s]+`)

const urlPrefix = "https://t.me/s/"
const imagePath = "/home/xigma/dev/project/XrayURIChecker/photo.jpg"
const dbPath = "file.db"

type Database struct {
	SentURLs map[string]bool
}

func main() {
	log := zerolog.New(zerolog.NewConsoleWriter(func(w *zerolog.ConsoleWriter) { w.Out = os.Stderr; w.TimeFormat = time.RFC3339 })).With().Timestamp().Logger().Level(zerolog.TraceLevel)
	if err := godotenv.Load(); nil != err {
		if !errors.Is(err, os.ErrNotExist) {
			log.Fatal().Err(err).Msg("unexpected error while loading .env file")
		}
		log.Warn().Msg(".env file not found")
	}
	db := &Database{
		SentURLs: make(map[string]bool),
	}

	err := db.loadDatabase()
	if err != nil {
		log.Error().Err(err).Msg("Failed to load database")
	}
	channelIDs, ok := os.LookupEnv(ChannelIDsEnvKeys)
	if !ok {
		log.Fatal().Str("key", BotTokenEnvKey).Msg("required environment variable is not set")
	}
	channelIDsSlice := strings.Split(channelIDs, ",")

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for _, channelIDsSlice := range channelIDsSlice {
		go fetchAndProcess(log, channelIDsSlice, db)
	}

	for range ticker.C {
		for _, channelIDsSlice := range channelIDsSlice {
			go fetchAndProcess(log, channelIDsSlice, db)
		}
	}

	select {}
}

func fetchAndProcess(log zerolog.Logger, channelID string, db *Database) {
	log.Info().Str("ChannelID:", channelID).Msg("Fetching new links...")

	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	res, err := client.Get(urlPrefix + channelID)
	if err != nil {
		log.Error().Err(err).Str("ChannelID:", channelID).Msg("Failed to fetch URL")
		return
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		log.Error().Str("Status Code", string(res.StatusCode)).Str("ChannelID:", channelID).Msg("Failed to fetch URL")
		return
	}

	doc, err := goquery.NewDocumentFromReader(res.Body)
	if err != nil {
		log.Error().Err(err).Str("ChannelID:", channelID).Msg("Failed to parse HTML")
		return
	}
	doc.Find(".tgme_widget_message_text").Each(func(i int, s *goquery.Selection) {
		text := s.Text()
		urls := re.FindAllString(text, -1)
		if len(urls) > 0 {
			log.Info().Str("ChannelID", channelID).Str("Message Number", string(i+1))
			for _, url := range urls {
				if _, exists := db.SentURLs[url]; !exists {
					modifiedURL := modifyURL(url)
					log.Info().Str("Modified Url:", modifiedURL)
					db.SentURLs[modifiedURL] = true
					latency, err := testURLWithXray(modifiedURL)
					if err != nil {
						log.Error().Err(err).Str("Url:", modifiedURL).Msg("Failed to test URL with xray")
						continue
					}
					if latency > 0 {
						err = sendToTelegram(log, channelID, modifiedURL, latency)
						if err != nil {
							log.Error().Err(err).Str("Url:", modifiedURL).Msg("Failed to send message to Telegram")
						}
					}
					time.Sleep(3 * time.Second)
				}
			}
		}
	})

	err = db.saveDatabase()
	if err != nil {
		log.Error().Err(err).Msg("Failed to save database")
	}
}

func modifyURL(url string) string {
	if strings.HasPrefix(url, "vless://") || strings.HasPrefix(url, "trojan://") || strings.HasPrefix(url, "ss://") {
		parts := strings.Split(url, "#")
		if len(parts) > 1 {
			parts[len(parts)-1] = "@ip_route"
			return strings.Join(parts, "#")
		}
	} else if strings.HasPrefix(url, "vmess://") {
		parts := strings.Split(url, "=")
		if len(parts) > 2 {
			return strings.Join(parts[:len(parts)-1], "=") // Keep everything before the last '='
		}
	}
	return url
}

func mdAutofixer(text string) string {
	// In MarkdownV2, these characters must be escaped: _ * [ ] ( ) ~ ` > # + - = | { } . !
	escapeChars := "_*[]()~>#+-=|{}.!"
	var sb strings.Builder
	for _, char := range text {
		if strings.ContainsRune(escapeChars, char) {
			sb.WriteString(fmt.Sprintf("\\%c", char))
		} else {
			sb.WriteRune(char)
		}
	}

	return sb.String()
}

func testURLWithXray(url string) (time.Duration, error) {
	//convert url to config.json file
	// run (xray run -c config.json) over localhost 10808 socks port
	//resbody , duration := CheckIp(xrayproxyURL)
	//latency := urlTest(log,proxyHost, proxyPort)
	var latency time.Duration = 100 * time.Millisecond
	return latency, nil
}

func sendToTelegram(log zerolog.Logger, channelID string, url string, latency time.Duration) error {
	botToken, ok := os.LookupEnv(BotTokenEnvKey)
	if !ok {
		log.Fatal().Str("key", BotTokenEnvKey).Msg("required environment variable is not set")
	}

	bot, err := tgbotapi.NewBotAPI(botToken)
	if err != nil {
		log.Error().Err(err).Msg("failed to create Telegram bot")
		return err
	}
	Text := fmt.Sprintf("🎉 #𝙉𝙚𝙬Config\n 💗Collected From: #%s\n`%s`\n\n📱اتصال با تمامی اپراتور ها\n• کافیست یکبار روی لینک کلیک کنید تا کپی گردد\n📣 کانال رسمی ما : @ip_routes\n\nLatency: %v", channelID, url, latency)
	messageText := mdAutofixer(Text)
	chatIDEnv, ok := os.LookupEnv(ChatIDEnvKey)
	chatID, err := strconv.ParseInt(chatIDEnv, 10, 64)
	if err != nil {
		log.Error().Err(err).Msg("Error converting string to int64")
		return err
	}
	if !ok {
		log.Fatal().Str("Chat ID:", chatIDEnv).Msg("required environment variable is not set")
	}
	photo := tgbotapi.NewPhotoUpload(chatID, imagePath)
	photo.Caption = messageText
	photo.ParseMode = "MarkdownV2"

	_, err = bot.Send(photo)
	if err != nil {
		log.Error().Err(err).Msg("failed to send photo to Telegram")
		return err
	} else {
		log.Info().Str("URI:", url).Msg("Uri Successfuly send to channel")
	}
	return nil
}

func (db *Database) loadDatabase() error {
	file, err := os.OpenFile(dbPath, os.O_RDONLY|os.O_CREATE, 0666)
	if err != nil {
		return err
	}
	defer file.Close()
	decoder := gob.NewDecoder(file)
	if err := decoder.Decode(&db.SentURLs); err != nil {
		return err
	}

	return nil
}

func (db *Database) saveDatabase() error {
	file, err := os.OpenFile(dbPath, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0666)
	if err != nil {
		return err
	}
	defer file.Close()
	encoder := gob.NewEncoder(file)
	if err := encoder.Encode(db.SentURLs); err != nil {
		return err
	}

	return nil
}
