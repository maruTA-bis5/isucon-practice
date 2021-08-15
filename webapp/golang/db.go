package xsuportal

import (
	"github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
	_ "github.com/newrelic/go-agent/v3/integrations/nrmysql"

	"github.com/go-redis/redis/v8"
	"github.com/isucon/isucon10-final/webapp/golang/util"
	nrredis "github.com/newrelic/go-agent/v3/integrations/nrredis-v8"
)

func GetDB() (*sqlx.DB, error) {
	mysqlConfig := mysql.NewConfig()
	mysqlConfig.Net = "tcp"
	mysqlConfig.Addr = util.GetEnv("MYSQL_HOSTNAME", "127.0.0.1") + ":" + util.GetEnv("MYSQL_PORT", "3306")
	mysqlConfig.User = util.GetEnv("MYSQL_USER", "isucon")
	mysqlConfig.Passwd = util.GetEnv("MYSQL_PASS", "isucon")
	mysqlConfig.DBName = util.GetEnv("MYSQL_DATABASE", "xsuportal")
	mysqlConfig.Params = map[string]string{
		"time_zone": "'+00:00'",
	}
	mysqlConfig.ParseTime = true
	mysqlConfig.InterpolateParams = true

	return sqlx.Open("nrmysql", mysqlConfig.FormatDSN())
}

func GetRedis() *redis.Client {
	opts := &redis.Options{Addr: "localhost:6379"}
	client := redis.NewClient(opts)
	client.AddHook(nrredis.NewHook(opts))

	return client
}
