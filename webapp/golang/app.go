package main

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/goccy/go-json"

	"github.com/gorilla/mux"
	"github.com/jmoiron/sqlx"
	"github.com/newrelic/go-agent/v3/integrations/nrgorilla"
	"github.com/newrelic/go-agent/v3/newrelic"
)

var (
	publicDir string
	fs        http.Handler
)

type User struct {
	ID        string    `db:"id" json:"id"`
	Email     string    `db:"email" json:"email"`
	Nickname  string    `db:"nickname" json:"nickname"`
	Staff     bool      `db:"staff" json:"staff"`
	CreatedAt time.Time `db:"created_at" json:"created_at"`
}

type Schedule struct {
	ID           string         `db:"id" json:"id"`
	Title        string         `db:"title" json:"title"`
	Capacity     int            `db:"capacity" json:"capacity"`
	Reserved     int            `db:"reserved" json:"reserved"`
	Reservations []*Reservation `db:"reservations" json:"reservations"`
	CreatedAt    time.Time      `db:"created_at" json:"created_at"`
}

type Reservation struct {
	ID         string    `db:"id" json:"id"`
	ScheduleID string    `db:"schedule_id" json:"schedule_id"`
	UserID     string    `db:"user_id" json:"user_id"`
	User       *User     `db:"user" json:"user"`
	CreatedAt  time.Time `db:"created_at" json:"created_at"`
}

func getCurrentUser(r *http.Request) *User {
	uidCookie, err := r.Cookie("user_id")
	if err != nil || uidCookie == nil {
		return nil
	}
	currentUser := r.Context().Value("currentUser")
	if currentUser != nil {
		return currentUser.(*User)
	}
	row := db.QueryRowxContext(r.Context(), "SELECT * FROM `users` WHERE `id` = ? LIMIT 1", uidCookie.Value)
	user := &User{}
	if err := row.StructScan(user); err != nil {
		return nil
	}
	return user
}

func requiredLogin(w http.ResponseWriter, r *http.Request) bool {
	if getCurrentUser(r) != nil {
		return true
	}
	sendErrorJSON(w, fmt.Errorf("login required"), 401)
	return false
}

func requiredStaffLogin(w http.ResponseWriter, r *http.Request) bool {
	if getCurrentUser(r) != nil && getCurrentUser(r).Staff {
		return true
	}
	sendErrorJSON(w, fmt.Errorf("login required"), 401)
	return false
}

func getReservations(r *http.Request, s *Schedule) error {
	rows, err := db.QueryxContext(r.Context(), "SELECT * FROM `reservations` WHERE `schedule_id` = ?", s.ID)
	if err != nil {
		return err
	}

	defer rows.Close()

	reserved := 0
	s.Reservations = []*Reservation{}
	var userIds []string
	for rows.Next() {
		reservation := &Reservation{}
		if err := rows.StructScan(reservation); err != nil {
			return err
		}
		userIds = append(userIds, reservation.UserID)

		s.Reservations = append(s.Reservations, reservation)
		reserved++
	}

	userById, err := bulkLoadUsers(r, userIds)
	if err != nil {
		return err
	}
	for _, r := range s.Reservations {
		usr := userById[r.UserID]
		r.User = &usr
	}
	s.Reserved = reserved

	return nil
}

func bulkLoadUsers(r *http.Request, userIds []string) (map[string]User, error) {
	c := r.Context()
	if len(userIds) == 0 {
		return make(map[string]User), nil
	}
	query, args, err := sqlx.In("SELECT * FROM users WHERE id IN (?)", userIds)
	if err != nil {
		return nil, err
	}
	var users []User
	err = db.SelectContext(c, &users, query, args...)
	if err != nil {
		return nil, err
	}
	userById := make(map[string]User)

	currentUser := getCurrentUser(r)
	for _, u := range users {
		id := u.ID

		if currentUser != nil && !currentUser.Staff {
			u.Email = ""
		}
		userById[id] = u
	}

	return userById, nil
}

func getReservationsCount(r *http.Request, s *Schedule) error {
	var count int64
	err := db.GetContext(r.Context(), &count, "SELECT Count(*) FROM `reservations` WHERE `schedule_id` = ?", s.ID)
	if err != nil {
		return err
	}

	s.Reserved = int(count)

	return nil
}

func getUser(r *http.Request, id string) *User {
	user := &User{}
	if err := db.QueryRowxContext(r.Context(), "SELECT * FROM `users` WHERE `id` = ? LIMIT 1", id).StructScan(user); err != nil {
		return nil
	}
	if getCurrentUser(r) != nil && !getCurrentUser(r).Staff {
		user.Email = ""
	}
	return user
}

func parseForm(r *http.Request) error {
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		return r.ParseForm()
	} else {
		return r.ParseMultipartForm(32 << 20)
	}
}

func serveMux(nrApp *newrelic.Application) http.Handler {
	router := mux.NewRouter()
	router.Use(nrgorilla.Middleware(nrApp))
	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			currentUser := getCurrentUser(r)
			context := context.WithValue(r.Context(), "currentUser", currentUser)
			next.ServeHTTP(w, r.WithContext(context))
		})
	})

	router.HandleFunc("/initialize", initializeHandler).Methods("POST")
	router.HandleFunc("/api/session", sessionHandler).Methods("GET")
	router.HandleFunc("/api/signup", signupHandler).Methods("POST")
	router.HandleFunc("/api/login", loginHandler).Methods("POST")
	router.HandleFunc("/api/schedules", createScheduleHandler).Methods("POST")
	router.HandleFunc("/api/reservations", createReservationHandler).Methods("POST")
	router.HandleFunc("/api/schedules", schedulesHandler).Methods("GET")
	router.HandleFunc("/api/schedules/{id}", scheduleHandler).Methods("GET")

	dir, err := filepath.Abs(filepath.Join(filepath.Dir(os.Args[0]), "..", "public"))
	if err != nil {
		log.Fatal(err)
	}
	publicDir = dir
	fs = http.FileServer(http.Dir(publicDir))

	router.PathPrefix("/").HandlerFunc(htmlHandler)

	return logger(router)
}

func logger(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		before := time.Now()
		handler.ServeHTTP(w, r)
		after := time.Now()
		duration := after.Sub(before)
		log.Printf("%s % 4s %s (%s)", r.RemoteAddr, r.Method, r.URL.Path, duration)
	})
}

func sendJSON(w http.ResponseWriter, data interface{}, statusCode int) error {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(statusCode)

	enc := json.NewEncoder(w)
	return enc.Encode(data)
}

func sendErrorJSON(w http.ResponseWriter, err error, statusCode int) error {
	log.Printf("ERROR: %+v", err)

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(statusCode)

	enc := json.NewEncoder(w)
	return enc.Encode(map[string]string{"error": err.Error()})
}

type initializeResponse struct {
	Language string `json:"language"`
}

func initializeHandler(w http.ResponseWriter, r *http.Request) {
	err := transaction(r.Context(), &sql.TxOptions{}, func(ctx context.Context, tx *sqlx.Tx) error {
		if _, err := tx.ExecContext(ctx, "TRUNCATE `reservations`"); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "TRUNCATE `schedules`"); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "TRUNCATE `users`"); err != nil {
			return err
		}

		id := generateID(tx, "users")
		if _, err := tx.ExecContext(
			ctx,
			"INSERT INTO `users` (`id`, `email`, `nickname`, `staff`, `created_at`) VALUES (?, ?, ?, true, NOW(6))",
			id,
			"isucon2021_prior@isucon.net",
			"isucon",
		); err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		sendErrorJSON(w, err, 500)
	} else {
		sendJSON(w, initializeResponse{Language: "golang"}, 200)
	}
}

func sessionHandler(w http.ResponseWriter, r *http.Request) {
	sendJSON(w, getCurrentUser(r), 200)
}

func signupHandler(w http.ResponseWriter, r *http.Request) {
	if err := parseForm(r); err != nil {
		sendErrorJSON(w, err, 500)
		return
	}

	user := &User{}

	err := transaction(r.Context(), &sql.TxOptions{}, func(ctx context.Context, tx *sqlx.Tx) error {
		email := r.FormValue("email")
		nickname := r.FormValue("nickname")
		id := generateID(tx, "users")

		if _, err := tx.ExecContext(
			ctx,
			"INSERT INTO `users` (`id`, `email`, `nickname`, `created_at`) VALUES (?, ?, ?, NOW(6))",
			id, email, nickname,
		); err != nil {
			return err
		}
		user.ID = id
		user.Email = email
		user.Nickname = nickname

		return tx.QueryRowContext(ctx, "SELECT `created_at` FROM `users` WHERE `id` = ? LIMIT 1", id).Scan(&user.CreatedAt)
	})

	if err != nil {
		sendErrorJSON(w, err, 500)
	} else {
		sendJSON(w, user, 200)
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if err := parseForm(r); err != nil {
		sendErrorJSON(w, err, 500)
		return
	}

	email := r.PostFormValue("email")
	user := &User{}

	if err := db.QueryRowxContext(
		r.Context(),
		"SELECT * FROM `users` WHERE `email` = ? LIMIT 1",
		email,
	).StructScan(user); err != nil {
		sendErrorJSON(w, err, 403)
		return
	}
	cookie := &http.Cookie{
		Name:     "user_id",
		Value:    user.ID,
		Path:     "/",
		MaxAge:   86400,
		HttpOnly: true,
	}
	http.SetCookie(w, cookie)

	sendJSON(w, user, 200)
}

func createScheduleHandler(w http.ResponseWriter, r *http.Request) {
	if err := parseForm(r); err != nil {
		sendErrorJSON(w, err, 500)
		return
	}

	if !requiredStaffLogin(w, r) {
		return
	}

	schedule := &Schedule{}
	err := transaction(r.Context(), &sql.TxOptions{}, func(ctx context.Context, tx *sqlx.Tx) error {
		id := generateID(tx, "schedules")
		title := r.PostFormValue("title")
		capacity, _ := strconv.Atoi(r.PostFormValue("capacity"))

		if _, err := tx.ExecContext(
			ctx,
			"INSERT INTO `schedules` (`id`, `title`, `capacity`, `created_at`) VALUES (?, ?, ?, NOW(6))",
			id, title, capacity,
		); err != nil {
			return err
		}
		if err := tx.QueryRowContext(ctx, "SELECT `created_at` FROM `schedules` WHERE `id` = ?", id).Scan(&schedule.CreatedAt); err != nil {
			return err
		}
		schedule.ID = id
		schedule.Title = title
		schedule.Capacity = capacity

		return nil
	})

	if err != nil {
		sendErrorJSON(w, err, 500)
	} else {
		sendJSON(w, schedule, 200)
	}
}

var scheduleMutexContainer *ScheduleMutexContainer = &ScheduleMutexContainer{
	mutexes: make(map[string]*sync.Mutex),
}

type ScheduleMutexContainer struct {
	mutexes map[string]*sync.Mutex
	mapLock sync.RWMutex
}

func (c *ScheduleMutexContainer) Lock(scheduleID string) {
	c.mapLock.Lock()

	scheduleLock := c.mutexes[scheduleID]
	if scheduleLock == nil {
		c.mutexes[scheduleID] = &sync.Mutex{}
	}
	c.mapLock.Unlock()

	scheduleLock.Lock()
}

func (c *ScheduleMutexContainer) Unlock(scheduleID string) {
	c.mapLock.RLock()

	scheduleLock := c.mutexes[scheduleID]
	if scheduleLock == nil {
		return
	}
	c.mapLock.RUnlock()

	scheduleLock.Unlock()
}

func createReservationHandler(w http.ResponseWriter, r *http.Request) {
	if err := parseForm(r); err != nil {
		sendErrorJSON(w, err, 500)
		return
	}

	if !requiredLogin(w, r) {
		return
	}

	reservation := &Reservation{}
	err := transaction(r.Context(), &sql.TxOptions{}, func(ctx context.Context, tx *sqlx.Tx) error {
		id := generateID(tx, "schedules")
		scheduleID := r.PostFormValue("schedule_id")
		userID := getCurrentUser(r).ID

		scheduleMutexContainer.Lock(scheduleID)
		defer scheduleMutexContainer.Unlock(scheduleID)

		var schedule *Schedule
		tx.QueryRowContext(ctx, "SELECT id, capacity FROM `schedules` WHERE `id` = ? LIMIT 1 FOR UPDATE", scheduleID).Scan(schedule)
		if schedule != nil {
			return sendErrorJSON(w, fmt.Errorf("schedule not found"), 403)
		}

		found := 0
		tx.QueryRowContext(ctx, "SELECT 1 FROM `users` WHERE `id` = ? LIMIT 1", userID).Scan(&found)
		if found != 1 {
			return sendErrorJSON(w, fmt.Errorf("user not found"), 403)
		}

		found = 0
		tx.QueryRowContext(ctx, "SELECT 1 FROM `reservations` WHERE `schedule_id` = ? AND `user_id` = ? LIMIT 1", scheduleID, userID).Scan(&found)
		if found == 1 {
			return sendErrorJSON(w, fmt.Errorf("already taken"), 403)
		}

		var reserved int
		err := tx.GetContext(ctx, &reserved, "SELECT Count(*) FROM `reservations` WHERE `schedule_id` = ?", scheduleID)
		if err != nil && err != sql.ErrNoRows {
			return sendErrorJSON(w, err, 500)
		}

		if reserved >= schedule.Capacity {
			return sendErrorJSON(w, fmt.Errorf("capacity is already full"), 403)
		}

		if _, err := tx.ExecContext(
			ctx,
			"INSERT INTO `reservations` (`id`, `schedule_id`, `user_id`, `created_at`) VALUES (?, ?, ?, NOW(6))",
			id, scheduleID, userID,
		); err != nil {
			return err
		}

		var createdAt time.Time
		if err := tx.QueryRowContext(ctx, "SELECT `created_at` FROM `reservations` WHERE `id` = ?", id).Scan(&createdAt); err != nil {
			return err
		}
		reservation.ID = id
		reservation.ScheduleID = scheduleID
		reservation.UserID = userID
		reservation.CreatedAt = createdAt

		return sendJSON(w, reservation, 200)
	})
	if err != nil {
		sendErrorJSON(w, err, 500)
	}
}

func schedulesHandler(w http.ResponseWriter, r *http.Request) {
	schedules := []*Schedule{}
	rows, err := db.QueryxContext(r.Context(), "SELECT * FROM `schedules` ORDER BY `id` DESC")
	if err != nil {
		sendErrorJSON(w, err, 500)
		return
	}

	var scheduleIds []string
	scheduleById := make(map[string]*Schedule)
	for rows.Next() {
		schedule := &Schedule{}
		if err := rows.StructScan(schedule); err != nil {
			sendErrorJSON(w, err, 500)
			return
		}
		if err := getReservationsCount(r, schedule); err != nil {
			sendErrorJSON(w, err, 500)
			return
		}
		schedules = append(schedules, schedule)
		scheduleById[schedule.ID] = schedule
	}
	reservationsBySchedule, err := bulkLoadReservationsCount(r, scheduleIds)
	if err != nil {
		sendErrorJSON(w, err, 500)
		return
	}
	for id, count := range reservationsBySchedule {
		scheduleById[id].Reserved = int(count)
	}

	sendJSON(w, schedules, 200)
}

func bulkLoadReservationsCount(r *http.Request, scheduleIds []string) (map[string]int64, error) {
	if len(scheduleIds) == 0 {
		return make(map[string]int64), nil
	}
	query, args, err := sqlx.In("SELECT schedule_id, Count(schedule_id) c FROM reservations WHERE schedule_id IN (?) GROUP BY schedule_id", scheduleIds)
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(r.Context(), query, args...)
	if err != nil {
		return nil, err
	}
	countById := make(map[string]int64)
	for rows.Next() {
		var r struct {
			ID    string `db:"schedule_id"`
			Count int64  `db:"c"`
		}
		if err := rows.Scan(&r); err != nil {
			return nil, err
		}
		countById[r.ID] = r.Count
	}
	return countById, nil
}

func scheduleHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	schedule := &Schedule{}
	if err := db.QueryRowxContext(r.Context(), "SELECT * FROM `schedules` WHERE `id` = ? LIMIT 1", id).StructScan(schedule); err != nil {

		sendErrorJSON(w, err, 500)
		return
	}

	if err := getReservations(r, schedule); err != nil {
		sendErrorJSON(w, err, 500)
		return
	}

	sendJSON(w, schedule, 200)
}

func htmlHandler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	realpath := filepath.Join(publicDir, path)

	if stat, err := os.Stat(realpath); !os.IsNotExist(err) && !stat.IsDir() {
		fs.ServeHTTP(w, r)
		return
	} else {
		realpath = filepath.Join(publicDir, "index.html")
	}

	file, err := os.Open(realpath)
	if err != nil {
		sendErrorJSON(w, err, 500)
		return
	}
	defer file.Close()

	w.Header().Set("Content-Type", "text/html; chartset=utf-8")
	w.WriteHeader(200)
	io.Copy(w, file)
}
