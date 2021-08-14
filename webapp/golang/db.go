package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"math/rand"
	"os"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/newrelic/go-agent/v3/integrations/nrmysql"
	"github.com/oklog/ulid/v2"
	"github.com/rs/xid"
)

var (
	db *sqlx.DB
)

var (
	entropy = ulid.Monotonic(rand.New(rand.NewSource(time.Now().UnixNano())), 0)
)

func Getenv(key string, defaultValue string) string {
	val := os.Getenv(key)
	if val == "" {
		return defaultValue
	} else {
		return val
	}
}

func init() {
	host := Getenv("DB_HOST", "127.0.0.1")
	port := Getenv("DB_PORT", "3306")
	user := Getenv("DB_USER", "isucon")
	pass := Getenv("DB_PASS", "isucon")
	name := Getenv("DB_NAME", "isucon2021_prior")

	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=true&interpolateParams=true", user, pass, host, port, name)

	var err error
	db, err = sqlx.Connect("nrmysql", dsn)
	if err != nil {
		log.Fatal(err)
	}
	db.SetConnMaxLifetime(10 * time.Second)
}

type transactionHandler func(context.Context, *sqlx.Tx) error

func transaction(ctx context.Context, opts *sql.TxOptions, handler transactionHandler) error {
	tx, err := db.BeginTxx(ctx, opts)
	if err != nil {
		return err
	}

	if err := handler(ctx, tx); err != nil {
		tx.Rollback()
		return err
	} else {
		return tx.Commit()
	}
}

func generateID(tx *sqlx.Tx, table string) string {
	return xid.New().String()
}
