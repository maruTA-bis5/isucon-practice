package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"math/rand"
	"os"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/jmoiron/sqlx"
	_ "github.com/newrelic/go-agent/v3/integrations/nrmysql"
	nrredis "github.com/newrelic/go-agent/v3/integrations/nrredis-v8"
	"github.com/newrelic/go-agent/v3/newrelic"
	"github.com/oklog/ulid/v2"
)

var (
	db  *sqlx.DB
	rdb *redis.Client
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

	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=true", user, pass, host, port, name)

	var err error
	db, err = sqlx.Connect("nrmysql", dsn)
	if err != nil {
		log.Fatal(err)
	}
	db.SetConnMaxLifetime(10 * time.Second)
}

func initRedisClient(nrApp *newrelic.Application) {
	opts := &redis.Options{
		Addr:     Getenv("REDIS_ADDR", "localhost:6379"),
		Password: "",
		DB:       0,
	}
	rdb = redis.NewClient(opts)
	rdb.AddHook(nrredis.NewHook(opts))
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
	id := ulid.MustNew(ulid.Timestamp(time.Now()), entropy).String()
	for {
		found := 0
		if err := tx.QueryRow(fmt.Sprintf("SELECT 1 FROM `%s` WHERE `id` = ? LIMIT 1", table), id).Scan(&found); err != nil {
			if err == sql.ErrNoRows {
				break
			}
			continue
		}
		if found == 0 {
			break
		}
		id = ulid.MustNew(ulid.Timestamp(time.Now()), entropy).String()
	}
	return id
}

func initCounter(c context.Context, key string) error {
	return rdb.WithContext(c).Set(c, key, 0, 0).Err()
}

func incr(c context.Context, key string) (int64, error) {
	return rdb.WithContext(c).Incr(c, key).Result()
}

func decr(c context.Context, key string) (int64, error) {
	return rdb.WithContext(c).Decr(c, key).Result()
}
