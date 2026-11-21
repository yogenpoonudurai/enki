package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/yogenpoonudurai/enki/internal/cloud"
)

func main() {
	adminKey := os.Getenv("ENKI_CLOUD_ADMIN_KEY")
	if adminKey == "" {
		log.Fatal("ENKI_CLOUD_ADMIN_KEY is required (used to mint API tokens)")
	}

	retention := 24 * time.Hour
	if v := os.Getenv("ENKI_RETENTION_HOURS"); v != "" {
		if hours, err := strconv.Atoi(v); err == nil && hours > 0 {
			retention = time.Duration(hours) * time.Hour
		}
	}

	store := cloud.NewMemoryStore()
	server := cloud.New(cloud.Config{
		AdminKey:            adminKey,
		StripeWebhookSecret: os.Getenv("ENKI_STRIPE_WEBHOOK_SECRET"),
		Model:               os.Getenv("ENKI_AI_MODEL"),
		Retention:           retention,
		Billing: cloud.BillingConfig{
			SecretKey:  os.Getenv("ENKI_STRIPE_SECRET_KEY"),
			PricePro:   os.Getenv("ENKI_STRIPE_PRICE_PRO"),
			PriceTeam:  os.Getenv("ENKI_STRIPE_PRICE_TEAM"),
			SuccessURL: os.Getenv("ENKI_STRIPE_SUCCESS_URL"),
			CancelURL:  os.Getenv("ENKI_STRIPE_CANCEL_URL"),
		},
	}, store)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go server.StartPurge(ctx, time.Hour)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("enki-cloud listening on :%s (retention %s)", port, retention)
	log.Fatal(http.ListenAndServe(":"+port, server.Handler()))
}
