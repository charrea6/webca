package webca

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
)

const (
	PORT       = 443
	PORTFIX    = 8000
	REQUEST    = "Request"
	LOGGEDUSER = "LoggedUser"
)

// address is a complex bind address
type address struct {
	addr, certfile, keyfile string
	tls                     bool
}

// fakedLogin for development environments
var fakedLogin bool

// portFix contains the port correction when low ports are not permited
var portFix int

// listenAndServe starts the server with or without TLS on the address
func (a address) listenAndServe(smux *http.ServeMux) error {
	if a.tls {
		return http.ListenAndServeTLS(a.addr, a.certfile, a.keyfile, smux)
	}
	return http.ListenAndServe(a.addr, smux)
}

// String prints this address properly
func (a address) String() string {
	prefix := "http"
	if a.tls {
		prefix = "https"
	}
	return prefix + "://" + a.addr
}

// templates contains all web templates
var templates *template.Template

// defaultHandler points to the handler for '/' requests
var defaultHandler func(w http.ResponseWriter, r *http.Request)

// PageStatus contains all values that a page and its templates need
// (including the SetupWizard when the setup is running)
//	U      User
// SetupWizard contains the status of the setup wizard and may be included in the PageStatus Map
//	CA     CertSetup
//	Cert   CertSetup
//	M      Mailer
type PageStatus map[string]interface{}

// init prepares all web templates before anything else
func init() {
	templates = template.New("webcaTemplates")
	templates.Funcs(template.FuncMap{
		// The name "title" is what the function will be called in the template text.
		"tr": tr, "indexOf": indexOf, "showPeriod": showPeriod, "qEsc": qEsc,
	})
	template.Must(templates.Parse(htmlTemplates))
	template.Must(templates.Parse(jsTemplates))
	template.Must(templates.Parse(pages))
	template.Must(templates.ParseFiles("style.css"))
}

// LoadCrt loads variables "Prfx" and "Crt" into PageSetup to point to the right
// CertSetup and its prefix and sets a default duration for that cert
func (ps PageStatus) LoadCrt(arg interface{}, prfx string, defaultDuration int) string {
	var cs *CertSetup
	if arg != nil {
		cs = arg.(*CertSetup)
	} else {
		cs = &CertSetup{}
	}
	ps["Crt"] = cs
	ps["Prfx"] = prfx
	cs.Duration = defaultDuration
	return ""
}

// IsDuration returns whether or not the given duration is the selected one on the loaded Crt
func (ps PageStatus) IsSelected(duration int) bool {
	crt := ps["Crt"]
	if crt == nil {
		return false
	}
	cs := crt.(*CertSetup)
	return cs.Duration == duration
}

// tr is the app translation function
func tr(s string, args ...interface{}) string {
	if args == nil || len(args) == 0 {
		return s
	}
	return fmt.Sprintf(s, args...)
}

// indexOf allows to access strings on a string array
func indexOf(sa []string, index int) string {
	if sa == nil || len(sa) < (index+1) {
		return ""
	}
	return sa[index]
}

// qEsc escapes a query string to be laced in the URL
func qEsc(s string, args ...interface{}) string {
	return url.QueryEscape(fmt.Sprintf(s, args...))
}

// WebCA starts the prepares and serves the WebApp
func WebCA() {
	smux := http.DefaultServeMux
	addr := PrepareServer(smux)
	err := addr.listenAndServe(smux)
	if portFix == 0 { // port Fixing is only applied once
		if err != nil {
			log.Printf("Could not start server on address %v!: %s\n", addr, err)
		}
		portFix = PORTFIX
		addr = fixAddress(addr)
		log.Printf("(Warning) Failed to listen on standard port, go to %v\n", addr)
		err = addr.listenAndServe(smux)
	}
	if err != nil {
		log.Fatalf("Could not start!: %s", err)
	}
}

// webCA will start the WebApp once it has been configured properly on a NEW http.ServeMux
func webCA() {
	smux := http.NewServeMux()
	addr := PrepareServer(smux)
	log.Printf("Go to %v\n", addr)
	err := addr.listenAndServe(smux)
	if err != nil {
		log.Fatalf("Could not start!: %s", err)
	}
}

// fixAddress returns a repaired alternate address by portFix
func fixAddress(a address) address {
	port := 80
	if strings.Contains(a.addr, ":") {
		parts := strings.Split(a.addr, ":")
		a.addr = parts[0]
		var err error
		port, err = strconv.Atoi(parts[1])
		if err != nil {
			port = 80
		}
	}
	a.addr = fmt.Sprintf("%s:%v", a.addr, port+portFix)
	return a
}

// prepareServer prepares the Web handlers for the setup wizard if there is no HTTPS config or
// the normal app if the app is already configured
func PrepareServer(smux *http.ServeMux) address {
	// load config...
	cfg := LoadConfig()
	if cfg == nil { // if config is empty then run the setup
		return PrepareSetup(smux) // always on the default serve mux
	}
	// otherwise start the normal app
	log.Printf("Starting WebCA normal startup...")
	smux.Handle("/", accessControl(index))
	smux.HandleFunc("/login", login)
	smux.Handle("/img/", http.StripPrefix("/img/", http.FileServer(http.Dir("img"))))
	smux.Handle("/favicon.ico", http.FileServer(http.Dir("img")))
	smux.Handle("/cert", accessControl(cert))
	smux.Handle("/gen", accessControl(gen))
	smux.Handle("/certControl", accessControl(certControl))
	smux.Handle("/cert/", authCertServer("/cert/", http.Dir(".")))
	smux.Handle("/renew", accessControl(renew))
	smux.Handle("/clone", accessControl(clone))
	smux.Handle("/del", accessControl(del))
	return address{webCAURL(cfg), certFile(cfg.getWebCert()), keyFile(cfg.getWebCert()), true}
}

// webCAURL returns the WebCA URL
func webCAURL(cfg *config) string {
	certName := cfg.getWebCert().Crt.Subject.CommonName
	return fmt.Sprintf("%s:%v", certName, PORT+portFix)
}

// authCertServer returns a authorized certServer for downloading certificates
func authCertServer(prefix string, dir http.Dir) http.Handler {
	return accessControlHandler(http.StripPrefix(prefix, certServer(dir)))
}

// certServer returns a certificate server filtering the downloadable cert files properly
func certServer(dir http.Dir) http.Handler {
	h := http.FileServer(dir)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, ".key.pem") && !strings.HasSuffix(r.URL.Path, ".pem") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-disposition", "attachment; filename="+r.URL.Path)
		w.Header().Set("Content-type", "application/x-pem-file")
		h.ServeHTTP(w, r)
	})
}

// readUser reads the user data from the request
func readUser(r *http.Request) User {
	u := User{}
	u.Username = r.FormValue("Username")
	u.Fullname = r.FormValue("Fullname")
	u.Email = r.FormValue("Email")
	u.Password = r.FormValue("Password")
	return u
}

// readCertSetup reads the certificate setup from the request
func readCertSetup(prefix string, r *http.Request) (*CertSetup, error) {
	cs := CertSetup{}
	prepareName(&cs.Name)
	cs.Name.CommonName = r.FormValue(prefix + ".CommonName")
	cs.Name.StreetAddress[0] = r.FormValue(prefix + ".StreetAddress")
	cs.Name.PostalCode[0] = r.FormValue(prefix + ".PostalCode")
	cs.Name.Locality[0] = r.FormValue(prefix + ".Locality")
	cs.Name.Province[0] = r.FormValue(prefix + ".Province")
	cs.Name.OrganizationalUnit[0] = r.FormValue(prefix + ".OrganizationalUnit")
	cs.Name.Organization[0] = r.FormValue(prefix + ".Organization")
	cs.Name.Country[0] = r.FormValue(prefix + ".Country")
	duration, err := strconv.Atoi(r.FormValue(prefix + ".Duration"))
	if err != nil || duration < 0 {
		return nil, fmt.Errorf("%s: %v", tr("Wrong duration!"), err)
	}
	cs.Duration = duration
	return &cs, nil
}

// readMailer reads the mailer config from the request
func readMailer(r *http.Request) Mailer {
	m := Mailer{}
	m.User = r.FormValue("M.User")
	m.Server = r.FormValue("M.Server")
	port := r.FormValue("M.Port")
	if port != "" {
		m.Server += ":" + port
	}
	m.Passwd = r.FormValue("M.Password")
	return m
}

// index displays the index page
func index(w http.ResponseWriter, r *http.Request) {
	ps := newLoggedPage(w, r)
	if ps == nil {
		return
	}
	ct := ListCerts()
	ps["CAs"] = ct.roots
	ps["Others"] = ct.foreign
	err := templates.ExecuteTemplate(w, "index", ps)
	handleError(w, r, err)
}

// setCertPageTexts sets cert's page texts for CA or Certs
func setCertPageTexts(ps PageStatus, parent string) {
	if parent != "" {
		ps["Title"] = tr("New Certificate at %s", parent)
		ps["CommonName"] = tr("Certificate Name")
		ps["Action"] = tr("Generate Certificate")
	} else {
		ps["Title"] = tr("New CA")
		ps["CommonName"] = tr("CA Name")
		ps["Action"] = tr("Generate CA")
	}
}

// cert allows the web user to generate a new certificate
func cert(w http.ResponseWriter, r *http.Request) {
	ps := newLoggedPage(w, r)
	if ps == nil {
		return
	}
	parent := r.FormValue("parent")
	if parent != "" {
		pc, err := FindCertOrFail(parent)
		if handleError(w, r, err) {
			return
		}
		pc.Crt.Subject.CommonName = ""
		ps["parent"] = parent
		ps["Cert"] = &CertSetup{Name: pc.Crt.Subject}
	}
	setCertPageTexts(ps, parent)
	err := templates.ExecuteTemplate(w, "cert", ps)
	handleError(w, r, err)
}

// gen will generate a certificate with the given request data
func gen(w http.ResponseWriter, r *http.Request) {
	ps := newLoggedPage(w, r)
	if ps == nil {
		return
	}
	parent := r.FormValue("parent")
	cs, err := readCertSetup("Cert", r)
	handleError(w, r, err)
	if cs.Name.CommonName == "" {
		ps["Error"] = tr("Can't create a certificate with no name!")
		ps["Cert"] = cs
		ps["parent"] = parent
		setCertPageTexts(ps, parent)
		err := templates.ExecuteTemplate(w, "cert", ps)
		handleError(w, r, err)
		return
	}
	if parent != "" {
		cacert := FindCert(parent)
		if handleError(w, r, err) {
			return
		}
		_, err = GenCert(cacert, cs.Name.CommonName, cs.Duration)
		if handleError(w, r, err) {
			return
		}
	} else {
		_, err := GenCACert(cs.Name, cs.Duration)
		if handleError(w, r, err) {
			return
		}
	}
	http.Redirect(w, r, "/", 302)
}

// certControl allows the web user to manage a certificate
func certControl(w http.ResponseWriter, r *http.Request) {
	ps := newLoggedPage(w, r)
	if ps == nil {
		return
	}
	cert := r.FormValue("cert")
	if cert != "" {
		c, err := FindCertOrFail(cert)
		if handleError(w, r, err) {
			return
		}
		ps["Cert"] = c
	}
	err := templates.ExecuteTemplate(w, "certControl", ps)
	handleError(w, r, err)
}

// renew the certificate requested
func renew(w http.ResponseWriter, r *http.Request) {
	ps := newLoggedPage(w, r)
	if ps == nil {
		return
	}
	cert := r.FormValue("cert")
	if cert != "" {
		c, err := FindCertOrFail(cert)
		if handleError(w, r, err) {
			return
		}
		c, err = RenewCert(c)
		if handleError(w, r, err) {
			return
		}
		ps["Cert"] = c
	}
	err := templates.ExecuteTemplate(w, "certControl", ps)
	handleError(w, r, err)
}

// clone the certificate requested
func clone(w http.ResponseWriter, r *http.Request) {
	ps := newLoggedPage(w, r)
	if ps == nil {
		return
	}
	cert := r.FormValue("cert")
	var err error
	if cert != "" {
		c, err := FindCertOrFail(cert)
		if handleError(w, r, err) {
			return
		}
		c = CloneCert(c, tr("clone of %v", c.Crt.Subject.CommonName))
		ps["Cert"] = c
		ps["parent"] = c.Parent.Crt.Subject.CommonName
		ps["Cert"] = &CertSetup{Name: c.Crt.Subject}
		setCertPageTexts(ps, c.Parent.Crt.Subject.CommonName)
		err = templates.ExecuteTemplate(w, "cert", ps)
	} else {
		err = fmt.Errorf("%s", tr("Nothing to clone!"))
	}
	handleError(w, r, err)
}

// del will try to remove the requested certificate if possible
func del(w http.ResponseWriter, r *http.Request) {
	ps := newLoggedPage(w, r)
	if ps == nil {
		return
	}
	cert := r.FormValue("cert")
	var err error
	if cert != "" {
		c, err := FindCertOrFail(cert)
		if handleError(w, r, err) {
			return
		}
		ps["Cert"] = c
		if c.Childs == nil || len(c.Childs) == 0 {
			DeleteCert(c)
			index(w, r)
			return
		} else if c.Crt.IsCA {
			ps["PendingConfirmation"] = true
			ps["Childs"] = c.Childs
		}
	}
	err = templates.ExecuteTemplate(w, "certControl", ps)
	handleError(w, r, err)
}

// newLoggedPage returns a page with a LOGGEDUSER attribute set to the current logged user
func newLoggedPage(w http.ResponseWriter, r *http.Request) PageStatus {
	s, err := SessionFor(w, r)
	if handleError(w, r, err) {
		return nil
	}
	ps := newPageStatus(r)
	ps[LOGGEDUSER] = s[LOGGEDUSER]
	return ps
}

// accessControl invokes handler h ONLY IF we are logged in, otherwise the login page
func accessControl(f func(w http.ResponseWriter, r *http.Request)) http.Handler {
	return accessControlHandler(http.HandlerFunc(f))
}

// accessControlHandler invokes handler h ONLY IF we are logged in, otherwise the login page
func accessControlHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, err := SessionFor(w, r)
		if handleError(w, r, err) {
			return
		}
		if s[LOGGEDUSER] == nil {
			if fakedLogin {
				s[LOGGEDUSER] = User{"fuser", "Faked User", "****", "fuser@fuser.com"}
				s.Save()
				h.ServeHTTP(w, r)
				return
			}
			ps := newPageStatus(r)
			ps[SESSIONID] = s.Id()
			err := templates.ExecuteTemplate(w, "login", ps)
			handleError(w, r, err)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// login handles login action
func login(w http.ResponseWriter, r *http.Request) {
	Username := r.FormValue("Username")
	Password := crypt(r.FormValue("Password"))
	cfg := LoadConfig()
	u := cfg.getUser(Username)
	if u.Password != Password {
		ps := newPageStatus(r)
		ps["Error"] = tr("Access Denied")
		err := templates.ExecuteTemplate(w, "login", ps)
		handleError(w, r, err)
		return
	} else {
		s, err := SessionFor(w, r)
		if handleError(w, r, err) {
			return
		}
		s[LOGGEDUSER] = u
		s.Save()
		targetUrl := r.FormValue("URL")
		if targetUrl == "" {
			targetUrl = "/"
		}
		http.Redirect(w, r, targetUrl, 302)
	}
}

// newPageStatus generates a new PageStatus including the Request
func newPageStatus(r *http.Request) PageStatus {
	ps := PageStatus{}
	ps[REQUEST] = r
	return ps
}

// fakeLogin fakes the login process
func FakeLogin() {
	fakedLogin = true
}

// FindCertOrFail fainds the certifcate or fails with an error
func FindCertOrFail(certname string) (*Cert, error) {
	cert := FindCert(certname)
	if cert != nil {
		return cert, nil
	}
	return nil, fmt.Errorf(tr("%v certificate not found!", cert))
}

// handleError displays err (if not nil) on Stderr and (if possible) displays a web error page
// it also returns true if the error was found and handled and false if err was nil
func handleError(w http.ResponseWriter, r *http.Request, err error) bool {
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return true
	}
	return false
}
