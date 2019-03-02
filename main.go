package main

import (
	"html/template"
	"net/http"

	uuid "github.com/satori/go.uuid"

	"golang.org/x/crypto/bcrypt"
)

type user struct {
	Username string
	Password []byte
}

var tpl *template.Template
var users = map[string]user{}
var sessions = map[string]string{}

func init() {
	tpl = template.Must(template.ParseGlob("templates/*"))
}

func main() {
	http.HandleFunc("/", index)
	http.HandleFunc("/register", register)
	http.HandleFunc("/romashka", romashka)
	http.Handle("/favicon.ico", http.NotFoundHandler())
	http.HandleFunc("/login", login)
	http.HandleFunc("/logout", logout)
	http.ListenAndServe(":8080", nil)
}

func index(w http.ResponseWriter, r *http.Request) {
	if u, ok := loggedIn(r); ok {

		tpl.ExecuteTemplate(w, "index.html", u)
		return
	}
	tpl.ExecuteTemplate(w, "index.html", nil)
}

func romashka(w http.ResponseWriter, r *http.Request) {
	u, ok := loggedIn(r)
	if !ok {
		w.Header().Set("Location", "/login")
		w.WriteHeader(http.StatusSeeOther)
		return
	}
	tpl.ExecuteTemplate(w, "romashka.html", u)

}

func register(w http.ResponseWriter, r *http.Request) {
	if _, ok := loggedIn(r); ok {
		w.Header().Set("Location", "/")
		w.WriteHeader(http.StatusSeeOther)
	}

	if r.Method == http.MethodPost {
		u := r.FormValue("username")
		if _, taken := users[u]; taken {
			http.Error(w, "Username is already used", http.StatusForbidden)
			return
		}
		p, _ := bcrypt.GenerateFromPassword([]byte(r.FormValue("password")), bcrypt.MinCost)
		users[u] = user{u, p}
		s, _ := uuid.NewV4()
		c := &http.Cookie{
			Name:   "session",
			Value:  s.String(),
			MaxAge: 5000,
		}
		http.SetCookie(w, c)
		sessions[c.Value] = u
		w.Header().Set("Location", "/")
		w.WriteHeader(http.StatusSeeOther)
		return
	}

	tpl.ExecuteTemplate(w, "register.html", nil)
}

func loggedIn(r *http.Request) (user, bool) {
	c, err := r.Cookie("session")
	if err != nil {
		return user{}, false
	}
	u := sessions[c.Value]
	us, logged := users[u]
	// update max-age
	return us, logged
}

func login(w http.ResponseWriter, r *http.Request) {
	if _, ok := loggedIn(r); ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if r.Method == http.MethodPost {
		u := r.FormValue("username")
		if _, exists := users[u]; !exists {
			http.Error(w, "Wrong username", http.StatusForbidden)
			return
		}
		err := bcrypt.CompareHashAndPassword(users[u].Password, []byte(r.FormValue("password")))
		if err != nil {
			http.Error(w, "Wrong password", http.StatusForbidden)
			return
		}
		var s string
		for key, value := range sessions { //somnitelnya realizatsiya
			if value == u {
				s = key
			}
		}

		c := &http.Cookie{
			Name:   "session",
			Value:  s,
			MaxAge: 5000,
		}
		http.SetCookie(w, c)
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
	tpl.ExecuteTemplate(w, "login.html", nil)
}

func logout(w http.ResponseWriter, r *http.Request) {
	if _, ok := loggedIn(r); !ok {

		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	c, _ := r.Cookie("session")

	c = &http.Cookie{
		Name:   "session",
		Value:  "",
		MaxAge: -1,
	}
	http.SetCookie(w, c)

	http.Redirect(w, r, "/", http.StatusSeeOther)
}
