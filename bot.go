package main

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"time"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"
	"github.com/joho/godotenv"
	"github.com/rs/zerolog"
)

func buildBot(log zerolog.Logger) {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	if err := godotenv.Load(); nil != err {
		if !errors.Is(err, os.ErrNotExist) {
			log.Fatal().Err(err).Msg("unexpected error while loading .env file")
		}
		log.Warn().Msg(".env file not found")
	}

	httpTransport := http.Transport{IdleConnTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second}
	httpClient := http.Client{Timeout: time.Second * 35, Transport: &httpTransport}
	proxyURL, ok := os.LookupEnv(BotHTTPProxyURL)
	if ok {
		httpProxyURL, err := url.Parse(proxyURL)
		if nil != err {
			log.Fatal().Err(err).Msg("failed to parse bot http proxy url")
		}
		httpTransport.Proxy = http.ProxyURL(httpProxyURL)
	}

	opts := []bot.Option{
		bot.WithDefaultHandler(handler),
		bot.WithCheckInitTimeout(30 * time.Second),
		bot.WithHTTPClient(30*time.Second, &httpClient),
	}
	token, ok := os.LookupEnv(BotTokenEnvKey)
	if !ok {
		log.Fatal().Str("key", BotTokenEnvKey).Msg("required environment variable is not set")
	}
	b, err := bot.New(token, opts...)
	if nil != err {
		log.Fatal().Err(err).Msg("failed to initialize bot instance")
	}
	b.Start(ctx)
}

func handler(ctx context.Context, b *bot.Bot, update *models.Update) {
	b.SendMessage(ctx, &bot.SendMessageParams{
		ChatID: update.Message.Chat.ID,
		Text:   update.Message.Text,
	})
}
