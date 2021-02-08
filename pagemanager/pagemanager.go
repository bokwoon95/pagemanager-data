package pagemanager

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/bokwoon95/erro"
	"github.com/gorilla/securecookie"
	_ "github.com/mattn/go-sqlite3"
	"github.com/microcosm-cc/bluemonday"
	"github.com/pelletier/go-toml"
	"golang.org/x/crypto/bcrypt"
)

var pagemanagerFS fs.FS

func init() {
	flag.Parse()
	_, currentFile, _, _ := runtime.Caller(0)
	currentDir := filepath.Join(currentFile, "..") + string(os.PathSeparator)
	if pagemanagerFS == nil {
		pagemanagerFS = os.DirFS(currentDir)
	}
}

type PageManager struct {
	dbdriver       string
	db             *sql.DB
	handlers       map[string]map[string]http.Handler
	datafolder     fs.FS
	fallbackassets map[string]string
	sanitizer      *bluemonday.Policy
	firsttime      bool
	restart        chan struct{}
	cookifier      *securecookie.SecureCookie
}

func (pm *PageManager) Middleware(next http.Handler) http.Handler {
	handlerFS := http.FileServer(filesystem{
		root:     http.FS(pm.datafolder),
		fallback: pm.fallbackassets,
		vroots: map[string]http.FileSystem{
			"pagemanager": http.FS(pagemanagerFS),
		},
	})
	mux := pm.newmux(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/pm-assets/") || strings.HasPrefix(r.URL.Path, "/pm-images/") {
			handlerFS.ServeHTTP(w, r)
			return
		}
		route, err := pm.getroute(r.URL.Path)
		if err != nil {
			http.Error(w, erro.Sdump(err), http.StatusInternalServerError)
			return
		}
		if route.Disabled.Valid && route.Disabled.Bool {
			http.NotFound(w, r)
			return
		}
		if route.RedirectURL.Valid {
			http.Redirect(w, r, route.RedirectURL.String, http.StatusMovedPermanently)
			return
		}
		if route.HandlerNamespace.Valid && route.HandlerName.Valid {
			handlers, ok := pm.handlers[route.HandlerNamespace.String]
			if !ok {
				http.Error(w, "No such handler namespace "+route.HandlerNamespace.String, http.StatusInternalServerError)
				return
			}
			handler, ok := handlers[route.HandlerName.String]
			if !ok {
				http.Error(w, "No such handler "+route.HandlerName.String, http.StatusInternalServerError)
				return
			}
			handler.ServeHTTP(w, r)
			return
		}
		if route.Content.Valid {
			io.WriteString(w, route.Content.String)
			return
		}
		if route.TemplateNamespace.Valid && route.TemplateName.Valid {
			path := filepath.Clean(filepath.Join("pm-assets", route.TemplateNamespace.String, route.TemplateName.String))
			t, err := template.New(filepath.Base(path)).Funcs(pm.FuncMap()).ParseFS(pm.datafolder, path)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			user, err := pm.sessionGet(w, r)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			_ = user
			data := make(map[string]interface{})
			env := make(map[string]interface{})
			env["EditMode"] = false
			env["PageID"] = r.URL.Path
			data["Env"] = env
			_ = r.ParseForm()
			if _, ok := r.Form["json"]; ok {
				b, err := json.Marshal(data)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				_, _ = w.Write(b)
				return
			}
			err = t.Execute(w, data)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func New() (*PageManager, error) {
	pm := &PageManager{}
	pm.firsttime = true
	err := pm.Setup()
	if err != nil {
		return pm, erro.Wrap(err)
	}
	return pm, nil
}

func (pm *PageManager) Setup() error {
	pm.restart = make(chan struct{}, 1)
	folderpath, err := LocateDataFolder()
	if err != nil {
		return erro.Wrap(err)
	}
	if folderpath == "" {
		return fmt.Errorf("couldn't locate PageManager datafolder")
	}
	// datafolder
	pm.datafolder = os.DirFS(folderpath)
	// db
	pm.dbdriver = "sqlite3"
	pm.db, err = sql.Open(pm.dbdriver, filepath.Join(folderpath, "database.sqlite3"))
	if err != nil {
		return erro.Wrap(err)
	}
	err = pm.db.Ping()
	if err != nil {
		return erro.Wrap(err)
	}
	_, err = pm.db.Exec("PRAGMA journal_mode = WAL")
	if err != nil {
		return erro.Wrap(err)
	}
	_, err = pm.db.Exec("PRAGMA synchronous = normal")
	if err != nil {
		return erro.Wrap(err)
	}
	_, err = pm.db.Exec("PRAGMA foreign_keys = ON")
	if err != nil {
		return erro.Wrap(err)
	}
	err = ensuretables(pm.dbdriver, pm.db)
	if err != nil {
		return erro.Wrap(err)
	}
	// bluemonday
	pm.sanitizer = bluemonday.UGCPolicy()
	pm.sanitizer.AllowStyling()
	// cookifier
	pm.cookifier = securecookie.New([]byte("hashkey"), []byte("encryptkey"))
	// fallbackassets
	if pm.fallbackassets == nil {
		pm.fallbackassets = make(map[string]string)
	}
	dir, err := pm.datafolder.Open("pm-assets")
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return erro.Wrap(err)
	}
	defer dir.Close()
	if dir, ok := dir.(interface {
		ReadDir(int) ([]fs.DirEntry, error)
	}); ok {
		for {
			entries, err := dir.ReadDir(1)
			if err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				return erro.Wrap(err)
			}
			if !entries[0].IsDir() {
				continue
			}
			err = func() error {
				f, err := pm.datafolder.Open(filepath.Join("pm-assets", entries[0].Name(), "fallback-assets.toml"))
				if err != nil {
					if errors.Is(err, fs.ErrNotExist) {
						return nil
					}
					return erro.Wrap(err)
				}
				defer f.Close()
				t, err := toml.LoadReader(f)
				if err != nil {
					return erro.Wrap(err)
				}
				for from, v := range t.ToMap() {
					to, ok := v.(string)
					if !ok {
						continue
					}
					pm.fallbackassets[from] = to
				}
				return nil
			}()
			if err != nil {
				return erro.Wrap(err)
			}
		}
	}
	return nil
}

type Route struct {
	URL               sql.NullString
	Disabled          sql.NullBool
	RedirectURL       sql.NullString
	HandlerNamespace  sql.NullString
	HandlerName       sql.NullString
	Content           sql.NullString
	TemplateNamespace sql.NullString
	TemplateName      sql.NullString
}

func (pm *PageManager) getroute(path string) (Route, error) {
	negapath := path
	if strings.HasSuffix(negapath, "/") {
		negapath = strings.TrimRight(negapath, "/")
	} else {
		negapath = negapath + "/"
	}
	var route Route
	query := `SELECT url, disabled, redirect_url, handler_namespace, handler_name, content, template_namespace, template_name
		FROM pm_routes WHERE url IN (?, ?)
		ORDER BY CASE url WHEN ? THEN 1 ELSE 2 END
		LIMIT 1`
	err := pm.db.
		QueryRow(query, path, negapath, path).
		Scan(&route.URL, &route.Disabled, &route.RedirectURL, &route.HandlerNamespace, &route.HandlerName, &route.Content, &route.TemplateNamespace, &route.TemplateName)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return route, erro.Wrap(err)
	}
	return route, nil
}

var datafolder = flag.String("pm-datafolder", "", "")

func LocateDataFolder() (string, error) {
	const datafoldername = "pagemanager-data"
	cwd, err := os.Getwd()
	if err != nil {
		return "", erro.Wrap(err)
	}
	userhome, err := os.UserHomeDir()
	if err != nil {
		return "", erro.Wrap(err)
	}
	exePath, err := os.Executable()
	if err != nil {
		return "", erro.Wrap(err)
	}
	exePath, err = filepath.EvalSymlinks(exePath)
	if err != nil {
		return "", erro.Wrap(err)
	}
	exeDir := filepath.Dir(exePath)
	paths := []string{
		cwd,                                     // $CWD
		filepath.Join(cwd, datafoldername),      // $CWD/pagemanager-data
		filepath.Join(userhome, datafoldername), // $HOME/pagemanager-data
		exeDir,                                  // $EXE_DIR
		filepath.Join(exeDir, datafoldername),   // $EXE_DIR/pagemanager-data
	}
	if *datafolder != "" {
		if strings.HasPrefix(*datafolder, ".") {
			return cwd + (*datafolder)[1:], nil
		}
		return *datafolder, nil
	}
	for _, path := range paths {
		if filepath.Base(path) != datafoldername {
			continue
		}
		dir, err := os.Open(path)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return "", erro.Wrap(err)
		}
		defer dir.Close()
		info, err := dir.Stat()
		if err != nil {
			return "", erro.Wrap(err)
		}
		if info.IsDir() {
			return path, nil
		}
	}
	return "", nil
}

type table struct {
	name        string
	columns     []column
	constraints []string
}

type column struct {
	name        string
	typ         string
	constraints []string
}

func (t table) ddl() string {
	buf := &strings.Builder{}
	buf.WriteString("CREATE TABLE ")
	buf.WriteString(t.name)
	buf.WriteString(" (")
	for i, c := range t.columns {
		buf.WriteString("\n    ")
		if i > 0 {
			buf.WriteString(",")
		}
		buf.WriteString(c.name)
		buf.WriteString(" ")
		buf.WriteString(c.typ)
		if len(c.constraints) > 0 {
			buf.WriteString(" ")
			buf.WriteString(strings.Join(c.constraints, " "))
		}
	}
	if len(t.constraints) > 0 {
		buf.WriteString("\n    ,")
		buf.WriteString(strings.Join(t.constraints, "\n    ,"))
	}
	buf.WriteString("\n)")
	return buf.String()
}

var tables = []table{
	{
		name: "pm_routes",
		columns: []column{
			{name: "url", typ: "TEXT", constraints: []string{"NOT NULL", "PRIMARY KEY"}},
			{name: "disabled", typ: "BOOLEAN"},
			{name: "redirect_url", typ: "TEXT"},
			{name: "handler_namespace", typ: "TEXT"},
			{name: "handler_name", typ: "TEXT"},
			{name: "content", typ: "TEXT"},
			{name: "template_namespace", typ: "TEXT"},
			{name: "template_name", typ: "TEXT"},
		},
	},
	{
		name: "pm_users",
		columns: []column{
			{name: "user_id", typ: "INTEGER", constraints: []string{"PRIMARY KEY"}}, // sqlite's INTEGER PRIMARY KEY == AUTOINCREMENT
			{name: "username", typ: "TEXT", constraints: []string{"NOT NULL", "UNIQUE"}},
			{name: "password_hash", typ: "TEXT"},
		},
	},
	{
		name: "pm_user_roles",
		columns: []column{
			{name: "user_role_id", typ: "BIGINT", constraints: []string{"NOT NULL", "PRIMARY KEY"}},
			{name: "user_id", typ: "BIGINT", constraints: []string{"NOT NULL"}},
			{name: "role", typ: "TEXT", constraints: []string{"NOT NULL"}},
		},
		constraints: []string{
			"UNIQUE (user_id, role)",
			"FOREIGN KEY (user_id) REFERENCES pm_users (user_id)",
		},
	},
	{
		name: "pm_sessions",
		columns: []column{
			{name: "session_hash", typ: "TEXT", constraints: []string{"NOT NULL", "PRIMARY KEY"}},
			{name: "user_id", typ: "BIGINT", constraints: []string{"NOT NULL"}},
			{name: "created_at", typ: "DATETIME"},
		},
		constraints: []string{
			"FOREIGN KEY (user_id) REFERENCES pm_users (user_id)",
		},
	},
	{
		name: "pm_templatedata",
		columns: []column{
			{name: "id", typ: "TEXT", constraints: []string{"NOT NULL", "PRIMARY KEY"}},
			{name: "data", typ: "JSON"},
		},
	},
}

func ensuretables(driver string, db *sql.DB) error {
	var err error
	for _, table := range tables {
		// does table exist?
		var exists sql.NullBool
		db.QueryRow("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name = ?)", table.name).Scan(&exists)
		// if not exists, create table from scratch and continue
		if !exists.Valid || !exists.Bool {
			_, err = db.Exec(table.ddl())
			if err != nil {
				return erro.Wrap(err)
			}
			continue
		}
		// do columns exist?
		columnset := make(map[string]struct{})
		rows, err := db.Query("SELECT name FROM pragma_table_info(?)", table.name)
		if err != nil {
			return erro.Wrap(err)
		}
		defer rows.Close()
		var name sql.NullString
		for rows.Next() {
			err = rows.Scan(&name)
			if err != nil {
				return erro.Wrap(err)
			}
			if name.Valid {
				columnset[name.String] = struct{}{}
			}
		}
		for _, column := range table.columns {
			if _, ok := columnset[column.name]; ok {
				continue
			}
			query := fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table.name, column.name, column.typ)
			if len(column.constraints) > 0 {
				query = query + strings.Join(column.constraints, " ")
			}
			_, err = db.Exec(query)
			if err != nil {
				return erro.Wrap(err)
			}
		}
	}
	return nil
}

func (pm *PageManager) ListenAndServe(addr string, handler http.Handler) error {
	for {
		if pm.firsttime {
			pm.firsttime = false
		} else {
			fmt.Println("restarted")
			err := pm.Setup()
			if err != nil {
				return erro.Wrap(err)
			}
		}
		srv := http.Server{
			Addr:    addr,
			Handler: handler,
		}
		go func() {
			<-pm.restart
			if err := srv.Shutdown(context.Background()); err != nil {
				log.Printf("srv.Shutdown error: %v\n", err)
			}
		}()
		fmt.Println("Listening on " + addr)
		err := srv.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			continue
		}
		return erro.Wrap(err)
	}
}

type filesystem struct {
	root     http.FileSystem
	fallback map[string]string
	vroots   map[string]http.FileSystem
}

func (pmfs filesystem) Open(name string) (http.File, error) {
	if i := strings.Index(name, "::"); i > 0 {
		vrootname := name[11:i]
		fsys, ok := pmfs.vroots[vrootname]
		if !ok {
			return nil, erro.Wrap(fmt.Errorf("no such vroot called " + vrootname + " (" + name + ")"))
		}
		newname := name[i+2:]
		if strings.HasPrefix(newname, "internal/") {
			return nil, fs.ErrNotExist
		}
		return fsys.Open(newname)
	}
	f, err := pmfs.root.Open(name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			fallback, ok := pmfs.fallback[name]
			if ok {
				f, err = pmfs.root.Open(fallback)
			}
		}
		if err != nil {
			return nil, err
		}
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if info.IsDir() {
		_ = f.Close()
		return nil, fs.ErrNotExist
	}
	return f, nil
}

func (pm *PageManager) newmux(defaultHandler http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/", defaultHandler)
	mux.HandleFunc("/restart", func(w http.ResponseWriter, r *http.Request) {
		select {
		case pm.restart <- struct{}{}:
		default:
		}
	})
	mux.HandleFunc("/pm-login", pm.login)
	mux.HandleFunc("/pm-signup", pm.signup)
	mux.HandleFunc("/pm-logout", func(w http.ResponseWriter, r *http.Request) {
		_, err := pm.db.Exec("DELETE FROM pm_sessions")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		http.Redirect(w, r, "/", http.StatusMovedPermanently)
	})
	return mux
}

func (pm *PageManager) login(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET", "":
		t, err := template.ParseFS(pagemanagerFS, "login.html")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		err = t.Execute(w, nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	case "POST":
		username := r.FormValue("pm-user-login")
		password := r.FormValue("pm-user-password")
		if username == "" || password == "" {
			http.Error(w, "username or password cannot be empty", http.StatusBadRequest)
			return
		}
		user, err := pm.authenticate(username, password)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		err = pm.sessionSet(w, r, user)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/", http.StatusMovedPermanently)
	default:
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	}
}

func (pm *PageManager) signup(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET", "":
		t, err := template.ParseFS(pagemanagerFS, "signup.html")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		err = t.Execute(w, nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	case "POST":
		username := r.FormValue("pm-user-login")
		password := r.FormValue("pm-user-password")
		if username == "" || password == "" {
			http.Error(w, "username or password cannot be empty", http.StatusBadRequest)
			return
		}
		user, err := pm.createuser(username, password)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		err = pm.sessionSet(w, r, user)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/", http.StatusMovedPermanently)
	default:
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	}
}

// TODO: the cookie needs to store the OG sessionKey. The database merely stores the hash of the sessionKey. To validate if a user's sessionKey (in their cookie) is a valid sessionKey, simply hash the sessionKey and check for its existence in the database.
// gorilla securecookie cannot do this because it handles the hashing internally for you. It was built to encode + hash a Go variable into a string, and it can decode + hash verify the string back into the Go variable.
// But that's not what I need, I need the intermediate hash because that's what I need to store inside the database. The actual content I'm interested in 'decoding' from the cookie is the hash, because my payload isn't some arbitrary Go variable, it's always a sessionKey (i.e. a plain string)

func randomstring(length int) string {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

type User struct {
	Valid    bool
	UserID   int64
	Username string
}

const hmackey = "hmackey"

func (pm *PageManager) createuser(username, password string) (user User, err error) {
	var exists bool
	err = pm.db.QueryRow("SELECT EXISTS(SELECT 1 FROM pm_users WHERE username = ?)", username).Scan(&exists)
	if err != nil {
		return user, erro.Wrap(err)
	}
	if exists {
		return user, erro.Wrap(fmt.Errorf("User with username %s already exists", username))
	}
	b, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return user, erro.Wrap(err)
	}
	res, err := pm.db.Exec("INSERT INTO pm_users (username, password_hash) VALUES (?, ?)", username, string(b))
	if err != nil {
		return user, erro.Wrap(err)
	}
	user.UserID, err = res.LastInsertId()
	if err != nil {
		return user, erro.Wrap(err)
	}
	user.Valid = true
	user.Username = username
	return user, nil
}

func (pm *PageManager) authenticate(username, password string) (user User, err error) {
	var userID sql.NullInt64
	var passwordHash sql.NullString
	err = pm.db.QueryRow("SELECT user_id, password_hash FROM pm_users WHERE username = ?", username).Scan(&userID, &passwordHash)
	if err != nil {
		return user, erro.Wrap(err)
	}
	if !passwordHash.Valid {
		return user, erro.Wrap(fmt.Errorf("user '%s' has no password", username))
	}
	err = bcrypt.CompareHashAndPassword([]byte(passwordHash.String), []byte(password))
	if err != nil {
		return user, erro.Wrap(err)
	}
	user.Valid = true
	user.UserID = userID.Int64
	user.Username = username
	return user, nil
}

func (pm *PageManager) sessionSet(w http.ResponseWriter, r *http.Request, user User) error {
	sessionKey := randomstring(32)
	h := hmac.New(sha256.New, []byte(hmackey))
	h.Write([]byte(sessionKey))
	sessionHash := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	_, err := pm.db.Exec("INSERT INTO pm_sessions (session_hash, user_id) VALUES (?, ?)", sessionHash, user.UserID)
	if err != nil {
		return erro.Wrap(err)
	}
	cookie := &http.Cookie{
		Name:  "pm_session_key",
		Value: sessionKey,
		Path:  "/",
		// Secure:   true,
		HttpOnly: true,
	}
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	http.SetCookie(w, cookie)
	return nil
}

func (pm *PageManager) sessionGet(w http.ResponseWriter, r *http.Request) (user User, err error) {
	cookie, err := r.Cookie("pm_session_key")
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			return user, nil
		}
		return user, erro.Wrap(err)
	}
	sessionKey := cookie.Value
	h := hmac.New(sha256.New, []byte(hmackey))
	h.Write([]byte(sessionKey))
	sessionHash := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	err = pm.db.QueryRow(`
	SELECT pm_users.user_id, pm_users.username
	FROM pm_users
	JOIN pm_sessions ON pm_sessions.user_id = pm_users.user_id
	WHERE pm_sessions.session_hash = ?
	`, sessionHash).Scan(&user.UserID, &user.Username)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return user, nil
		}
		return user, erro.Wrap(err)
	}
	user.Valid = true
	return user, nil
}

func (pm *PageManager) FuncMap() map[string]interface{} {
	funcmap := map[string]interface{}{
		"safeHTML":       func(s string) template.HTML { return template.HTML(s) },
		"safeJS":         func(s string) template.JS { return template.JS(s) },
		"getValue":       pm.getValue,
		"getValueWithID": pm.getValueWithID,
		"getRows":        pm.getRows,
		"getRowsWithID":  pm.getRowsWithID,
		"notNull":        notNull,
	}
	return funcmap
}

func (pm *PageManager) getValue(env map[string]interface{}, key string) (interface{}, error) {
	id, ok := env["PageID"].(string)
	if !ok {
		return nil, nil
	}
	return pm.getValueWithID(env, key, id)
}

func (pm *PageManager) getValueWithID(env map[string]interface{}, key, id string) (interface{}, error) {
	var value sql.NullString
	query := "SELECT json_extract(data, ?) FROM pm_templatedata WHERE id = ?"
	err := pm.db.QueryRow(query, "$."+key, id).Scan(&value)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if value.Valid {
		return value.String, nil
	}
	return nil, nil
}

func notNull(val interface{}) bool {
	if val == nil {
		return false
	}
	switch val := val.(type) {
	case string:
		return true
	case sql.NullString:
		return val.Valid
	default:
		return false
	}
}

func (pm *PageManager) getRows(env map[string]interface{}, key string) ([]interface{}, error) {
	id, ok := env["PageID"].(string)
	if !ok {
		return nil, nil
	}
	return pm.getRowsWithID(env, key, id)
}

func (pm *PageManager) getRowsWithID(env map[string]interface{}, key, id string) ([]interface{}, error) {
	var s sql.NullString
	query := "SELECT json_extract(data, ?) FROM pm_templatedata WHERE id = ?"
	id = strings.TrimSuffix(id, "/edit")
	err := pm.db.QueryRow(query, "$."+key, id).Scan(&s)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	var array []interface{}
	if s.Valid {
		err = json.Unmarshal([]byte(s.String), &array)
		if err != nil {
			return array, err
		}
		return array, nil
	}
	return nil, nil
}
