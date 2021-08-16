package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/jmoiron/sqlx"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	redis "github.com/go-redis/redis/v8"
	"github.com/newrelic/go-agent/v3/integrations/nrgrpc"
	"github.com/newrelic/go-agent/v3/newrelic"

	xsuportal "github.com/isucon/isucon10-final/webapp/golang"
	"github.com/isucon/isucon10-final/webapp/golang/proto/xsuportal/resources"
	"github.com/isucon/isucon10-final/webapp/golang/proto/xsuportal/services/bench"
	"github.com/isucon/isucon10-final/webapp/golang/util"
)

var db *sqlx.DB
var nrEnabled bool
var notifier *xsuportal.Notifier
var rdb *redis.Client

type benchmarkQueueService struct {
}

func (b *benchmarkQueueService) Svc() *bench.BenchmarkQueueService {
	return &bench.BenchmarkQueueService{
		ReceiveBenchmarkJob: b.ReceiveBenchmarkJob,
	}
}

func (b *benchmarkQueueService) ReceiveBenchmarkJob(ctx context.Context, req *bench.ReceiveBenchmarkJobRequest) (*bench.ReceiveBenchmarkJobResponse, error) {
	var jobHandle *bench.ReceiveBenchmarkJobResponse_JobHandle
	for {
		next, err := func() (bool, error) {
			tx, err := db.Beginx()
			if err != nil {
				return false, fmt.Errorf("begin tx: %w", err)
			}
			defer tx.Rollback()

			job, err := pollBenchmarkJob(ctx, tx)
			if err != nil {
				return false, fmt.Errorf("poll benchmark job: %w", err)
			}
			if job == nil {
				return false, nil
			}

			var gotLock bool
			err = tx.GetContext(
				ctx,
				&gotLock,
				"SELECT 1 FROM `benchmark_jobs` WHERE `id` = ? AND `status` = ? FOR UPDATE",
				job.ID,
				resources.BenchmarkJob_PENDING,
			)
			if err == sql.ErrNoRows {
				return true, nil
			}
			if err != nil {
				return false, fmt.Errorf("get benchmark job with lock: %w", err)
			}
			randomBytes := make([]byte, 16)
			_, err = rand.Read(randomBytes)
			if err != nil {
				return false, fmt.Errorf("read random: %w", err)
			}
			handle := base64.StdEncoding.EncodeToString(randomBytes)
			_, err = tx.ExecContext(
				ctx,
				"UPDATE `benchmark_jobs` SET `status` = ?, `handle` = ? WHERE `id` = ? AND `status` = ? LIMIT 1",
				resources.BenchmarkJob_SENT,
				handle,
				job.ID,
				resources.BenchmarkJob_PENDING,
			)
			if err != nil {
				return false, fmt.Errorf("update benchmark job status: %w", err)
			}

			var contestStartsAt time.Time
			err = tx.GetContext(ctx, &contestStartsAt, "SELECT `contest_starts_at` FROM `contest_config` LIMIT 1")
			if err != nil {
				return false, fmt.Errorf("get contest starts at: %w", err)
			}

			if err := tx.Commit(); err != nil {
				return false, fmt.Errorf("commit tx: %w", err)
			}

			jobHandle = &bench.ReceiveBenchmarkJobResponse_JobHandle{
				JobId:            job.ID,
				Handle:           handle,
				TargetHostname:   job.TargetHostName,
				ContestStartedAt: timestamppb.New(contestStartsAt),
				JobCreatedAt:     timestamppb.New(job.CreatedAt),
			}
			return false, nil
		}()
		if err != nil {
			return nil, fmt.Errorf("fetch queue: %w", err)
		}
		if !next {
			break
		}
	}
	if jobHandle != nil {
		log.Printf("[DEBUG] Dequeued: job_handle=%+v", jobHandle)
	}
	return &bench.ReceiveBenchmarkJobResponse{
		JobHandle: jobHandle,
	}, nil
}

type benchmarkReportService struct {
}

func (b *benchmarkReportService) Svc() *bench.BenchmarkReportService {
	return &bench.BenchmarkReportService{
		ReportBenchmarkResult: b.ReportBenchmarkResult,
	}
}

func (b *benchmarkReportService) ReportBenchmarkResult(srv bench.BenchmarkReport_ReportBenchmarkResultServer) error {
	var notifier xsuportal.Notifier
	for {
		req, err := srv.Recv()
		if err != nil {
			return err
		}
		if req.Result == nil {
			return status.Error(codes.InvalidArgument, "result required")
		}

		err = func() error {
			if nrEnabled {
				defer newrelic.FromContext(srv.Context()).StartSegment("ReportBenchmarkResultInner").End()
			}
			tx, err := db.Beginx()
			if err != nil {
				return fmt.Errorf("begin tx: %w", err)
			}
			defer tx.Rollback()

			var job xsuportal.BenchmarkJob
			err = tx.GetContext(
				srv.Context(),
				&job,
				"SELECT * FROM `benchmark_jobs` WHERE `id` = ? AND `handle` = ? LIMIT 1 FOR UPDATE",
				req.JobId,
				req.Handle,
			)
			if err == sql.ErrNoRows {
				log.Printf("[ERROR] Job not found: job_id=%v, handle=%+v", req.JobId, req.Handle)
				return status.Errorf(codes.NotFound, "Job %d not found or handle is wrong", req.JobId)
			}
			if err != nil {
				return fmt.Errorf("get benchmark job: %w", err)
			}
			if req.Result.Finished {
				log.Printf("[DEBUG] %v: save as finished", req.JobId)
				if err := b.saveAsFinished(srv.Context(), tx, &job, req); err != nil {
					return err
				}
				if err := tx.Commit(); err != nil {
					return fmt.Errorf("commit tx: %w", err)
				}
				if err := notifier.NotifyBenchmarkJobFinished(srv.Context(), db, &job); err != nil {
					return fmt.Errorf("notify benchmark job finished: %w", err)
				}
			} else {
				log.Printf("[DEBUG] %v: save as running", req.JobId)
				if err := b.saveAsRunning(srv.Context(), tx, &job, req); err != nil {
					return err
				}
				if err := tx.Commit(); err != nil {
					return fmt.Errorf("commit tx: %w", err)
				}
			}
			return nil
		}()
		if err != nil {
			return err
		}
		err = srv.Send(&bench.ReportBenchmarkResultResponse{
			AckedNonce: req.GetNonce(),
		})
		if err != nil {
			return fmt.Errorf("send report: %w", err)
		}
	}
}

func (b *benchmarkReportService) saveAsFinished(ctx context.Context, db *sqlx.Tx, job *xsuportal.BenchmarkJob, req *bench.ReportBenchmarkResultRequest) error {
	if !job.StartedAt.Valid || job.FinishedAt.Valid {
		return status.Errorf(codes.FailedPrecondition, "Job %v has already finished or has not started yet", req.JobId)
	}
	if req.Result.MarkedAt == nil {
		return status.Errorf(codes.InvalidArgument, "marked_at is required")
	}
	markedAt := req.Result.MarkedAt.AsTime().Round(time.Microsecond)
	if nrEnabled {
		defer newrelic.FromContext(ctx).StartSegment("saveAsFinished").End()
	}

	result := req.Result
	var raw, deduction sql.NullInt32
	if result.ScoreBreakdown != nil {
		raw.Valid = true
		raw.Int32 = int32(result.ScoreBreakdown.Raw)
		deduction.Valid = true
		deduction.Int32 = int32(result.ScoreBreakdown.Deduction)
	}
	_, err := db.ExecContext(
		ctx,
		"UPDATE `benchmark_jobs` SET `status` = ?, `score_raw` = ?, `score_deduction` = ?, `passed` = ?, `reason` = ?, `updated_at` = NOW(6), `finished_at` = ? WHERE `id` = ? LIMIT 1",
		resources.BenchmarkJob_FINISHED,
		raw,
		deduction,
		result.Passed,
		result.Reason,
		markedAt,
		req.JobId,
	)
	if err != nil {
		return fmt.Errorf("update benchmark job status: %w", err)
	}
	job.FinishedAt.Time = markedAt
	err = b.updateTeamScore(ctx, db, job)
	if err != nil {
		return fmt.Errorf("update team stat: %w", err)
	}
	return nil
}

func (b *benchmarkReportService) updateTeamScore(ctx context.Context, db *sqlx.Tx, job *xsuportal.BenchmarkJob) error {
	if nrEnabled {
		defer newrelic.FromContext(ctx).StartSegment("updateTeamScore").End()
	}
	latestScore := job.Score()
	score := &xsuportal.TeamScore{}
	err := db.GetContext(ctx, score, "SELECT * FROM team_score WHERE team_id = ? LIMIT 1 FOR UPDATE", job.TeamID)
	if err == sql.ErrNoRows {
		_, err := db.ExecContext(
			ctx,
			"INSERT INTO team_score(team_id, best_score, best_score_started_at, best_score_marked_at, latest_score, latest_score_started_at, latest_score_marked_at, finish_count) VALUES(?,?,?,?,?,?,?,1)",
			job.TeamID,
			latestScore,
			job.StartedAt.Time,
			job.FinishedAt.Time,
			latestScore,
			job.StartedAt.Time,
			job.FinishedAt.Time,
		)
		if err != nil {
			return fmt.Errorf("insert team score: %w", err)
		}
		return nil
	}
	score.UpdateScore(job)
	_, err = db.ExecContext(
		ctx,
		"UPDATE team_score SET best_score = ?, best_score_started_at = ?, best_score_marked_at = ?, latest_score = ?, latest_score_started_at = ?, latest_score_marked_at = ?, finish_count = (SELECT COUNT(*) FROM benchmark_jobs WHERE team_id = ? AND finished_at IS NOT NULL) WHERE team_id = ?",
		score.BestScore.Int64,
		score.BestScoreStartedAt.Time,
		score.BestScoreMarkedAt.Time,
		score.LatestScore.Int64,
		score.LatestScoreStartedAt.Time,
		score.LatestScoreMarkedAt.Time,
		job.TeamID,
		job.TeamID,
	)
	if err != nil {
		return fmt.Errorf("update team score for team[%d]: %w", job.TeamID, err)
	}
	return nil
}

func (b *benchmarkReportService) saveAsRunning(ctx context.Context, db *sqlx.Tx, job *xsuportal.BenchmarkJob, req *bench.ReportBenchmarkResultRequest) error {
	if req.Result.MarkedAt == nil {
		return status.Errorf(codes.InvalidArgument, "marked_at is required")
	}
	if nrEnabled {
		defer newrelic.FromContext(ctx).StartSegment(("saveAsRunning")).End()
	}
	var startedAt time.Time
	if job.StartedAt.Valid {
		startedAt = job.StartedAt.Time
	} else {
		startedAt = req.Result.MarkedAt.AsTime().Round(time.Microsecond)
	}
	_, err := db.ExecContext(
		ctx,
		"UPDATE `benchmark_jobs` SET `status` = ?, `score_raw` = NULL, `score_deduction` = NULL, `passed` = FALSE, `reason` = NULL, `started_at` = ?, `updated_at` = NOW(6), `finished_at` = NULL WHERE `id` = ? LIMIT 1",
		resources.BenchmarkJob_RUNNING,
		startedAt,
		req.JobId,
	)
	if err != nil {
		return fmt.Errorf("update benchmark job status: %w", err)
	}
	return nil
}

const BENCH_JOBS_KEY = "benchmark_jobs"

func pollBenchmarkJob(ctx context.Context, db sqlx.QueryerContext) (*xsuportal.BenchmarkJob, error) {
	for i := 0; i < 10; i++ {
		popped := rdb.WithContext(ctx).BRPop(ctx, 5*time.Second, BENCH_JOBS_KEY).Val()

		var idStr string
		if len(popped) == 1 {
			idStr = popped[0]
		} else if len(popped) == 2 {
			idStr = popped[1]
		} else {
			continue
		}
		id, err := strconv.Atoi(idStr)
		if err != nil {
			return nil, fmt.Errorf("Invalid id stored in queue: id=%s, %w", idStr, err)
		}
		var job xsuportal.BenchmarkJob
		err = sqlx.GetContext(ctx, db, &job, "SELECT * FROM benchmark_jobs WHERE id = ?", id)
		if err == sql.ErrNoRows {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("get benchmark job: %w", err)
		}
		return &job, nil
	}
	return nil, nil
}

func main() {
	port := util.GetEnv("PORT", "50051")
	address := ":" + port

	listener, err := net.Listen("tcp", address)
	if err != nil {
		panic(err)
	}
	log.Print("[INFO] listen ", address)

	db, _ = xsuportal.GetDB()
	db.SetMaxOpenConns(util.GetEnvInt("XSU_DB_MAX_CONN", 20))

	var server *grpc.Server

	nrLicense := util.GetEnv("NEWRELIC_LICENSE", "")
	var nrApp *newrelic.Application
	if nrLicense != "" {
		nrApp, err = newrelic.NewApplication(
			newrelic.ConfigAppName("xsubench"),
			newrelic.ConfigLicense(nrLicense),
			newrelic.ConfigDebugLogger(os.Stdout),
			func(cfg *newrelic.Config) {
				cfg.CustomInsightsEvents.Enabled = true
			},
		)
		if err != nil {
			panic(err)
		}
		server = grpc.NewServer(
			grpc.UnaryInterceptor(nrgrpc.UnaryServerInterceptor(nrApp)),
			grpc.StreamInterceptor(nrgrpc.StreamServerInterceptor(nrApp)),
		)
		nrEnabled = true
	} else {
		server = grpc.NewServer()
		nrEnabled = false
	}

	rdb = xsuportal.GetRedisClient(nrEnabled)

	notifier = xsuportal.NewNotifier(nrApp)

	queue := &benchmarkQueueService{}
	report := &benchmarkReportService{}

	bench.RegisterBenchmarkQueueService(server, queue.Svc())
	bench.RegisterBenchmarkReportService(server, report.Svc())

	if err := server.Serve(listener); err != nil {
		panic(err)
	}
}
