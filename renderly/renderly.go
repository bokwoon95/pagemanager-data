package renderly

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"text/template/parse"

	"github.com/bokwoon95/erro"
	"github.com/google/uuid"
	"github.com/oxtoacart/bpool"
)

type Asset struct {
	Data string
	hash [32]byte
}

type EnvFunc func(w io.Writer, r *http.Request, env map[string]interface{}) error

type Plugin struct {
	pluginID          string
	InitErr           error
	FuncMap           map[string]interface{}
	Fsys              fs.FS
	EnvFuncs          map[string]EnvFunc
	Components        []Component
	GlobalCSS         []string
	GlobalJS          []string
	GlobalHTMLEnvFunc []string
	GlobalJSEnvFunc   []string
}

type Component struct {
	pluginID     string
	HTML         *template.Template
	CSS          []string
	JS           []string
	HTMLEnvFuncs []string
	JSEnvFuncs   []string
}

type Page struct {
	html         *template.Template
	css          []string
	js           []string
	htmlenvfuncs []string
	jsenvfuncs   []string
	// copied from *Renderly struct
	bufpool    *bpool.BufferPool
	envfuncs   map[string]EnvFunc
	fsys       muxFS
	fsysprefix string
}

type Renderly struct {
	mu         *sync.RWMutex
	bufpool    *bpool.BufferPool
	fsys       muxFS
	funcmap    map[string]interface{}
	opts       []string
	fsysprefix string
	// plugins
	basetemplate       *template.Template
	components         map[string]Component
	envfuncs           map[string]EnvFunc
	globalcss          []string
	globaljs           []string
	globalhtmlenvfuncs []string
	globaljsenvfuncs   []string
	errorhandler       func(http.ResponseWriter, *http.Request, error)
	fileserver         http.Handler
}

type muxFS struct {
	defaultFS fs.FS
	altFS     map[string]fs.FS
}

func (ry *Renderly) Fsys() fs.FS { return ry.fsys }

type Option func(*Renderly) error

func New(fsys fs.FS, opts ...Option) (*Renderly, error) {
	ry := &Renderly{
		mu:         &sync.RWMutex{},
		fsys:       muxFS{defaultFS: fsys, altFS: make(map[string]fs.FS)},
		fsysprefix: "static",
		bufpool:    bpool.NewBufferPool(64),
		funcmap:    make(map[string]interface{}),
		// plugin
		basetemplate: template.New(""),
		envfuncs:     make(map[string]EnvFunc),
	}
	ry.fileserver = http.FileServer(http.FS(ry.fsys))
	var err error
	for _, opt := range opts {
		err = opt(ry)
		if err != nil {
			return ry, erro.Wrap(err)
		}
	}
	// ry.cacheenabled = true
	return ry, nil
}

func dedupkeys(keys []string) []string {
	set := make(map[string]struct{})
	n := 0
	for _, key := range keys {
		if _, ok := set[key]; ok {
			continue
		}
		set[key] = struct{}{}
		keys[n] = key
		n++
	}
	keys = keys[:n]
	return keys
}

func categorize(names []string) (html, css, js []string) {
	for _, name := range names {
		truncatedName := name
		// if i := strings.IndexRune(name, '?'); i > 0 {
		// 	truncatedName = name[:i]
		// }
		ext := strings.ToLower(filepath.Ext(truncatedName))
		switch ext {
		case ".css":
			css = append(css, name)
		case ".js":
			js = append(js, name)
		default:
			html = append(html, name)
		}
	}
	return html, css, js
}

// Open implements fs.FS, which can be converted to a http.Filesystem using http.FS
func (muxfs muxFS) Open(name string) (fs.File, error) {
	var fsys = muxfs.defaultFS
	if i := strings.Index(name, "::"); i > 0 {
		fsysName := name[:i]
		altfs := muxfs.altFS[fsysName]
		if altfs != nil {
			fsys = altfs
		}
		name = name[i+2:]
	}
	return fsys.Open(name)
}

func (muxfs muxFS) ReadFile(filename string) ([]byte, error) {
	// ReadFile copied from function of the same name in
	// $GOROOT/src/io/fs/readfile.go, with minor adjustments.
	//
	// Copyright 2020 The Go Authors. All rights reserved.
	// Use of this source code is governed by a BSD-style
	// license that can be found in the LICENSE file.
	file, err := muxfs.Open(filename)
	if err != nil {
		return nil, erro.Wrap(err)
	}
	defer file.Close()
	var size int
	if info, err := file.Stat(); err == nil {
		size64 := info.Size()
		if int64(int(size64)) == size64 {
			size = int(size64)
		}
	}
	data := make([]byte, 0, size+1)
	for {
		if len(data) >= cap(data) {
			d := append(data[:cap(data)], 0)
			data = d[:len(data)]
		}
		n, err := file.Read(data[len(data):cap(data)])
		data = data[:len(data)+n]
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			return data, erro.Wrap(err)
		}
	}
}

func (ry *Renderly) FileServer() http.Handler {
	return ry.fileserver
}

func (ry *Renderly) FileServerMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		var prefix string
		if ry.fsysprefix != "" {
			prefix = "/" + strings.Trim(ry.fsysprefix, "/") + "/"
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasPrefix(r.URL.Path, prefix) {
				next.ServeHTTP(w, r)
				return
			}
			p := strings.TrimPrefix(r.URL.Path, prefix)
			rp := strings.TrimPrefix(r.URL.RawPath, prefix)
			r2 := &http.Request{}
			*r2 = *r
			r2.URL = &url.URL{}
			*r2.URL = *r.URL
			r2.URL.Path = p
			r2.URL.RawPath = rp
			ry.fileserver.ServeHTTP(w, r2)
		})
	}
}

func addParseTree(parent, child *template.Template, childName string) error {
	var err error
	if childName == "" {
		childName = child.Name()
	}
	for _, t := range child.Templates() {
		if t == child {
			_, err = parent.AddParseTree(childName, t.Tree)
			if err != nil {
				return erro.Wrap(err)
			}
			continue
		}
		_, err = parent.AddParseTree(t.Name(), t.Tree)
		if err != nil {
			return erro.Wrap(err)
		}
	}
	return nil
}

func executeTemplate(t *template.Template, bufpool *bpool.BufferPool, w io.Writer, name string, data interface{}) error {
	tempbuf := bufpool.Get()
	defer bufpool.Put(tempbuf)
	err := t.ExecuteTemplate(tempbuf, name, data)
	if err != nil {
		return erro.Wrap(err)
	}
	if w, ok := w.(http.ResponseWriter); ok {
		// need to explicitly set content type so that chi middleware.Compressor will work
		_ = w
		w.Header().Set("Content-Type", http.DetectContentType(tempbuf.Bytes()))
	}
	_, err = tempbuf.WriteTo(w)
	if err != nil {
		return erro.Wrap(err)
	}
	return nil
}

// TODO: rewrite the recursive part into a loop
func listAllDeps(t *template.Template, name string) ([]string, error) {
	t = t.Lookup(name) // set the main template to `name`
	if t == nil {
		return nil, fmt.Errorf(`no such template "%s"`, name)
	}
	var allnames = []string{t.Name()}
	var set = make(map[string]struct{})
	var root parse.Node = t.Tree.Root
	var roots []parse.Node
	for {
		names := listDeps(root)
		for _, name := range names {
			if _, ok := set[name]; ok {
				continue
			}
			set[name] = struct{}{}
			allnames = append(allnames, name)
			t = t.Lookup(name)
			if t == nil {
				return allnames, fmt.Errorf(`{{ template "%s" }} was referenced, but was not found`, name)
			}
			roots = append(roots, t.Tree.Root)
		}
		if len(roots) == 0 {
			break
		}
		root, roots = roots[0], roots[1:]
	}
	return allnames, nil
}

func listDeps(node parse.Node) []string {
	var names []string
	switch node := node.(type) {
	case *parse.TemplateNode:
		names = append(names, node.Name)
	case *parse.ListNode:
		for _, n := range node.Nodes {
			names = append(names, listDeps(n)...)
		}
	}
	return names
}

func FsysPrefix(prefix string) Option {
	return func(ry *Renderly) error {
		ry.fsysprefix = prefix
		return nil
	}
}

func TemplateFuncs(funcmaps ...map[string]interface{}) Option {
	return func(ry *Renderly) error {
		if ry.funcmap == nil {
			ry.funcmap = make(map[string]interface{})
		}
		for _, funcmap := range funcmaps {
			for name, fn := range funcmap {
				ry.funcmap[name] = fn
			}
		}
		return nil
	}
}

func TemplateOpts(option ...string) Option {
	return func(ry *Renderly) error {
		ry.opts = option
		return nil
	}
}

func GlobalCSS(filenames ...string) Option {
	return func(ry *Renderly) error {
		ry.globalcss = append(ry.globalcss, filenames...)
		return nil
	}
}

func GlobalJS(filenames ...string) Option {
	return func(ry *Renderly) error {
		ry.globaljs = append(ry.globaljs, filenames...)
		return nil
	}
}

func GlobalTemplates(fsys fs.FS, filenames ...string) Option {
	return func(ry *Renderly) error {
		if ry.basetemplate == nil {
			ry.basetemplate = template.New("")
		}
		for _, name := range filenames {
			b, err := fs.ReadFile(fsys, name)
			if err != nil {
				return erro.Wrap(err)
			}
			t, err := template.New(name).Funcs(ry.funcmap).Option(ry.opts...).Parse(string(b))
			if err != nil {
				return erro.Wrap(err)
			}
			err = addParseTree(ry.basetemplate, t, t.Name())
			if err != nil {
				return erro.Wrap(err)
			}
		}
		return nil
	}
}

func GlobalHTMLEnvFuncs(fns ...EnvFunc) Option {
	return func(ry *Renderly) error {
		for _, fn := range fns {
			name := uuid.New().String()
			ry.envfuncs[name] = fn
			ry.globalhtmlenvfuncs = append(ry.globalhtmlenvfuncs, name)
		}
		return nil
	}
}

func GlobalJSEnvFuncs(fns ...EnvFunc) Option {
	return func(ry *Renderly) error {
		for _, fn := range fns {
			name := uuid.New().String()
			ry.envfuncs[name] = fn
			ry.globaljsenvfuncs = append(ry.globaljsenvfuncs, name)
		}
		return nil
	}
}

func AddFS(name string, fsys fs.FS) Option {
	return func(ry *Renderly) error {
		ry.fsys.altFS[name] = fsys
		return nil
	}
}

func URLPrefix(prefix string) Option {
	return func(ry *Renderly) error {
		ry.fsysprefix = prefix
		return nil
	}
}

func AbsDir(relativePath string) string {
	_, absolutePath, _, _ := runtime.Caller(1)
	return filepath.Join(absolutePath, "..", relativePath) + string(os.PathSeparator)
}

func Plugins(plugins ...Plugin) Option {
	return func(ry *Renderly) error {
		if ry.basetemplate == nil {
			ry.basetemplate = template.New("")
		}
		for _, plugin := range plugins {
			if plugin.InitErr != nil {
				return erro.Wrap(plugin.InitErr)
			}
			pluginID := uuid.New().String()
			for _, component := range plugin.Components {
				if component.HTML == nil {
					return erro.Wrap(fmt.Errorf("component with nil template"))
				}
				name := component.HTML.Name()
				component.pluginID = pluginID
				ry.components[name] = component
				// err := addParseTree(ry.basetemplate, component.HTML, name) // TODO: actually I don't want to put all component templates into the basetemplate
				// if err != nil {
				// 	return erro.Wrap(err)
				// }
			}
			ry.fsys.altFS[pluginID] = plugin.Fsys
			for name, fn := range plugin.EnvFuncs {
				ry.envfuncs[pluginID+"::"+name] = fn
			}
			for name, fn := range plugin.FuncMap {
				ry.funcmap[name] = fn
			}
			for _, name := range plugin.GlobalCSS {
				ry.globalcss = append(ry.globalcss, pluginID+"::"+name)
			}
			for _, name := range plugin.GlobalJS {
				ry.globaljs = append(ry.globaljs, pluginID+"::"+name)
			}
			for _, name := range plugin.GlobalHTMLEnvFunc {
				ry.globalhtmlenvfuncs = append(ry.globalhtmlenvfuncs, pluginID+"::"+name)
			}
			for _, name := range plugin.GlobalJSEnvFunc {
				ry.globaljsenvfuncs = append(ry.globaljsenvfuncs, pluginID+"::"+name)
			}
		}
		return nil
	}
}

func AppendCSP(w http.ResponseWriter, policy, value string) error {
	const key = "Content-Security-Policy"
	if value == "" {
		return nil
	}
	CSP := w.Header().Get(key)
	if CSP == "" {
		// w.Header().Set(key, policy+" "+value)
		return nil
	}
	CSP = strings.ReplaceAll(CSP, "\n", " ") // newlines screw up the regex matching, remove them
	re, err := regexp.Compile(`(.*` + policy + `[^;]*)(;|$)(.*)`)
	if err != nil {
		return erro.Wrap(err)
	}
	matches := re.FindStringSubmatch(CSP)
	if len(matches) == 0 {
		w.Header().Set(key, CSP+"; "+policy+" "+value)
		return nil
	}
	newCSP := matches[1] + " " + value + matches[2] + matches[3]
	w.Header().Set(key, newCSP)
	return nil
}

func ExistsCSP(w http.ResponseWriter, policy, value string) bool {
	const key = "Content-Security-Policy"
	if value == "" {
		return false
	}
	CSP := w.Header().Get(key)
	if CSP == "" {
		// w.Header().Set(key, policy+" "+value)
		return false
	}
	policyGroups := strings.Split(CSP, ";")
	for _, policyGroup := range policyGroups {
		policyGroup := strings.TrimSpace(policyGroup)
		if strings.HasPrefix(policyGroup, policy) {
			if strings.Contains(policyGroup, value) {
				return true
			}
			return false
		}
	}
	return false
}

func (page Page) CSS(inline bool) (styles template.HTML, CSP string, err error) {
	stylesbuf := &strings.Builder{}
	CSPbuf := &strings.Builder{}
	if !inline {
		for _, name := range page.css {
			if stylesbuf.Len() > 0 {
				stylesbuf.WriteString("\n")
			}
			stylesbuf.WriteString(`<link rel="stylesheet" href="/`)
			stylesbuf.WriteString(strings.Trim(page.fsysprefix, "/"))
			stylesbuf.WriteString("/")
			stylesbuf.WriteString(name)
			stylesbuf.WriteString(`">`)
		}
	} else {
		for _, name := range page.css {
			if stylesbuf.Len() > 0 {
				stylesbuf.WriteString("\n")
			}
			if CSPbuf.Len() > 0 {
				CSPbuf.WriteString(" ")
			}
			b, err := page.fsys.ReadFile(name)
			if err != nil {
				return "", "", erro.Wrap(err)
			}
			stylesbuf.WriteString("<style>")
			_, _ = stylesbuf.Write(b)
			stylesbuf.WriteString("</style>")
			hash := sha256.Sum256(b)
			CSPbuf.WriteString("'sha256-")
			CSPbuf.WriteString(base64.StdEncoding.EncodeToString(hash[0:]))
			CSPbuf.WriteString("'")
		}
	}
	return template.HTML(stylesbuf.String()), strings.TrimSpace(CSPbuf.String()), nil
}

func (page Page) JS(jsenv map[string]interface{}, inline bool) (scripts template.HTML, CSP string, err error) {
	scriptsbuf := &strings.Builder{}
	CSPbuf := &strings.Builder{}
	b, err := json.Marshal(jsenv)
	if err != nil {
		return "", "", erro.Wrap(err)
	}
	b = bytes.ReplaceAll(b, []byte(`"`), []byte(`\"`))
	envscript := `window.Env = (function () {
  const env = JSON.parse("` + string(b) + `");
  return function (key) {
    if (key === undefined) {
      return JSON.parse(JSON.stringify(env));
    }
    const val = env[key];
    if (val === undefined) {
      return undefined;
    }
    return JSON.parse(JSON.stringify(val));
  };
})();`
	envhash := sha256.Sum256([]byte(envscript))
	scriptsbuf.WriteString("<script>")
	scriptsbuf.WriteString(envscript)
	scriptsbuf.WriteString("</script>")
	CSPbuf.WriteString("'sha256-")
	CSPbuf.WriteString(base64.StdEncoding.EncodeToString(envhash[0:]))
	CSPbuf.WriteString("'")
	if !inline {
		for _, name := range page.js {
			if scriptsbuf.Len() > 0 {
				scriptsbuf.WriteString("\n")
			}
			scriptsbuf.WriteString(`<script src="/`)
			scriptsbuf.WriteString(strings.Trim(page.fsysprefix, "/"))
			scriptsbuf.WriteString("/")
			scriptsbuf.WriteString(name)
			scriptsbuf.WriteString(`"></script>`)
		}
	} else {
		for _, name := range page.js {
			if scriptsbuf.Len() > 0 {
				scriptsbuf.WriteString("\n")
			}
			if CSPbuf.Len() > 0 {
				CSPbuf.WriteString(" ")
			}
			b, err := page.fsys.ReadFile(name)
			if err != nil {
				return "", "", erro.Wrap(err)
			}
			scriptsbuf.WriteString("<script>")
			_, _ = scriptsbuf.Write(b)
			scriptsbuf.WriteString("</script>")
			hash := sha256.Sum256(b)
			CSPbuf.WriteString("'sha256-")
			CSPbuf.WriteString(base64.StdEncoding.EncodeToString(hash[0:]))
			CSPbuf.WriteString("'")
		}
	}
	return template.HTML(scriptsbuf.String()), strings.TrimSpace(CSPbuf.String()), nil
}

type RenderOption func(*RenderConfig)

type RenderConfig struct {
	htmlenv      map[string]interface{}
	jsenv        map[string]interface{}
	jsonifydata  bool
	inlineassets bool
	csp          map[string][]string
}

func JSEnv(jsenv map[string]interface{}) RenderOption {
	return func(config *RenderConfig) {
		for name, value := range jsenv {
			config.jsenv[name] = value
		}
	}
}

func HTMLEnv(htmlenv map[string]interface{}) RenderOption {
	return func(config *RenderConfig) {
		for name, value := range htmlenv {
			config.htmlenv[name] = value
		}
	}
}

func JSONifyData(jsonify bool) RenderOption {
	return func(config *RenderConfig) {
		config.jsonifydata = jsonify
	}
}

func InlineAssets(inline bool) RenderOption {
	return func(config *RenderConfig) {
		config.inlineassets = inline
	}
}

func CSP(csp map[string][]string) RenderOption {
	return func(config *RenderConfig) {
		for name, values := range csp {
			config.csp[name] = append(config.csp[name], values...)
		}
	}
}

func (ry *Renderly) Page(w io.Writer, r *http.Request, mainfile string, includefiles []string, data interface{}, opts ...RenderOption) error {
	page, err := ry.Lookup(mainfile, includefiles...)
	if err != nil {
		return erro.Wrap(err)
	}
	err = page.Render(w, r, data, opts...)
	if err != nil {
		return erro.Wrap(err)
	}
	return nil
}

func (ry *Renderly) Lookup(mainfile string, includefiles ...string) (Page, error) {
	var err error
	// Else construct the page from scratch
	page := Page{
		bufpool:    ry.bufpool,
		envfuncs:   ry.envfuncs,
		fsys:       ry.fsys,
		fsysprefix: ry.fsysprefix,
	}
	// Clone the page template from the base template
	page.html, err = ry.basetemplate.Clone()
	if err != nil {
		return page, erro.Wrap(err)
	}
	page.html = page.html.Funcs(ry.funcmap).Option(ry.opts...)
	HTMLFiles, CSSFiles, JSFiles := categorize(includefiles)
	// Add user-specified HTML templates to the page template
	for _, filename := range append([]string{mainfile}, HTMLFiles...) {
		var t *template.Template
		// Else construct the template from scratch
		if t == nil {
			b, err := ry.fsys.ReadFile(filename)
			if err != nil {
				return page, erro.Wrap(err)
			}
			t, err = template.New(filename).Funcs(ry.funcmap).Option(ry.opts...).Parse(string(b))
			if err != nil {
				return page, erro.Wrap(err)
			}
		}
		// Add to page template
		err := addParseTree(page.html, t, t.Name())
		if err != nil {
			return page, erro.Wrap(err)
		}
	}
	page.html = page.html.Lookup(mainfile)
	if page.html == nil {
		return page, fmt.Errorf(`no template found for name "%s"`, mainfile)
	}
	// Add global assets/envfuncs
	page.css = append(page.css, ry.globalcss...)
	page.js = append(page.js, ry.globaljs...)
	page.htmlenvfuncs = append(page.htmlenvfuncs, ry.globalhtmlenvfuncs...)
	page.jsenvfuncs = append(page.jsenvfuncs, ry.globaljsenvfuncs...)
	// Find the list of dependency templates invoked by the main HTML template
	depedencies, err := listAllDeps(page.html, mainfile)
	if err != nil {
		return page, erro.Wrap(err)
	}
	// For each depedency template, figure out the corresponding set of
	// CSS/JS/HTMLEnvFuncs/JSEnvFuncs to include in the page.
	for _, componentName := range depedencies {
		if t := page.html.Lookup(componentName); t != nil {
			continue
		}
		component, ok := ry.components[componentName]
		if !ok {
			return page, erro.Wrap(fmt.Errorf("{{ template %s }} was referenced but does not exist", componentName))
		}
		err = addParseTree(page.html, component.HTML, componentName)
		if err != nil {
			return page, erro.Wrap(err)
		}
		for _, name := range component.CSS {
			page.css = append(page.css, component.pluginID+"::"+name)
		}
		for _, name := range component.JS {
			page.js = append(page.js, component.pluginID+"::"+name)
		}
		for _, name := range component.HTMLEnvFuncs {
			page.htmlenvfuncs = append(page.htmlenvfuncs, component.pluginID+"::"+name)
		}
		for _, name := range component.JSEnvFuncs {
			page.jsenvfuncs = append(page.jsenvfuncs, component.pluginID+"::"+name)
		}
	}
	// Add the user-specified CSS files to the page
	for _, name := range CSSFiles {
		page.css = append(page.css, name)
	}
	// Add the user-specified JS files to the page
	for _, name := range JSFiles {
		page.js = append(page.js, name)
	}
	page.css = dedupkeys(page.css)
	page.js = dedupkeys(page.js)
	page.htmlenvfuncs = dedupkeys(page.htmlenvfuncs)
	page.jsenvfuncs = dedupkeys(page.jsenvfuncs)
	return page, nil
}

func (page Page) Render(w io.Writer, r *http.Request, data interface{}, opts ...RenderOption) error {
	if data == nil {
		data = make(map[string]interface{})
	}
	if page.bufpool == nil || page.html == nil {
		return fmt.Errorf("tried to render an empty page")
	}
	config := &RenderConfig{
		htmlenv: make(map[string]interface{}),
		jsenv:   make(map[string]interface{}),
		csp:     make(map[string][]string),
	}
	for _, opt := range opts {
		opt(config)
	}
	htmlenv := make(map[string]interface{})
	jsenv := make(map[string]interface{})
	switch data := data.(type) {
	case map[string]interface{}:
		env, _ := data["Env"].(map[string]interface{})
		if env != nil {
			htmlenv = env
		} else {
			data["Env"] = htmlenv
		}
	default:
		vptr := reflect.ValueOf(data)
		v := reflect.Indirect(vptr)
		if v.Kind() != reflect.Struct {
			break
		}
		vtype := v.Type()
		for i := 0; i < v.NumField(); i++ {
			if vtype.Field(i).Tag.Get("renderly") != "Env" {
				continue
			}
			field := v.Field(i)
			switch env := field.Interface().(type) {
			case map[string]interface{}:
				if !field.CanSet() {
					if vptr.Kind() == v.Kind() {
						return erro.Wrap(fmt.Errorf("unable to set tagged field, please pass in a pointer instead"))
					}
					return erro.Wrap(fmt.Errorf("unable to set field tagged `Env`"))
				}
				if env != nil {
					htmlenv = env
				} else {
					field.Set(reflect.ValueOf(htmlenv)) // NOTE: may panic if type don't match
				}
			default:
				return erro.Wrap(fmt.Errorf("tagged field is not a map[string]interface{}"))
			}
			break
		}
	}
	var err error
	for _, key := range page.htmlenvfuncs {
		fn := page.envfuncs[key]
		if fn == nil {
			return erro.Wrap(fmt.Errorf("function %+v is nil or doesn't exist", key))
		}
		err = fn(w, r, htmlenv)
		if err != nil {
			return erro.Wrap(err)
		}
	}
	for key, value := range config.htmlenv {
		htmlenv[key] = value
	}
	for _, key := range page.jsenvfuncs {
		fn := page.envfuncs[key]
		if fn == nil {
			return erro.Wrap(fmt.Errorf("function %+v is nil or doesn't exist", key))
		}
		err = fn(w, r, jsenv)
		if err != nil {
			return erro.Wrap(err)
		}
	}
	for key, value := range config.jsenv {
		jsenv[key] = value
	}
	var styles, scripts template.HTML
	var stylesCSP, scriptsCSP string
	styles, stylesCSP, err = page.CSS(config.inlineassets)
	if err != nil {
		return erro.Wrap(err)
	}
	htmlenv["CSS"] = styles
	scripts, scriptsCSP, err = page.JS(jsenv, config.inlineassets)
	if err != nil {
		return erro.Wrap(err)
	}
	htmlenv["JS"] = scripts
	var selfstyles, selfscripts bool
	if styles != "" && !config.inlineassets {
		selfstyles = true
	}
	if scripts != "" && !config.inlineassets {
		selfscripts = true
	}
	CSP := &strings.Builder{}
	if w, ok := w.(http.ResponseWriter); ok {
		// style-src
		_ = AppendCSP(w, "style-src", stylesCSP)
		if selfstyles && !ExistsCSP(w, "style-src", "'self'") {
			_ = AppendCSP(w, "style-src", "'self'")
		}
		// script-src
		_ = AppendCSP(w, "script-src", scriptsCSP)
		if selfscripts && !ExistsCSP(w, "script-src", "'self'") {
			_ = AppendCSP(w, "script-src", "'self'")
		}
		CSP.WriteString(w.Header().Get("Content-Security-Policy"))
	}
	if CSP.Len() == 0 {
		CSP.WriteString("style-src")
		if selfstyles {
			if CSP.Len() > 0 {
				CSP.WriteString(" ")
			}
			CSP.WriteString("'self'")
		}
		if stylesCSP != "" {
			if CSP.Len() > 0 {
				CSP.WriteString(" ")
			}
			CSP.WriteString(stylesCSP)
		}
		if CSP.Len() > 0 {
			CSP.WriteString("; ")
		}
		CSP.WriteString("script-src")
		if selfscripts {
			if CSP.Len() > 0 {
				CSP.WriteString(" ")
			}
			CSP.WriteString("'self'")
		}
		if scriptsCSP != "" {
			if CSP.Len() > 0 {
				CSP.WriteString(" ")
			}
			CSP.WriteString(scriptsCSP)
		}
	}
	htmlenv["ContentSecurityPolicy"] = template.HTML(`<meta http-equiv="Content-Security-Policy" content="` + CSP.String() + `">`)
	if config.jsonifydata {
		b, err := json.Marshal(data)
		if err != nil {
			return erro.Wrap(err)
		}
		if w, ok := w.(http.ResponseWriter); ok {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(b)
		}
		return nil
	}
	err = executeTemplate(page.html, page.bufpool, w, page.html.Name(), data)
	if err != nil {
		return erro.Wrap(err)
	}
	return nil
}
