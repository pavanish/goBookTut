package main

import (
	"net/http"

	"github.com/gorilla/mux"

	"./views"
)

var (
	homeView    *views.View
	contactView *views.View
	signupView  *views.View
)

//var homeTemplate *template.Template
//var contactTemplate *template.Template

func main() {
	homeView = views.NewView("bootstrap", "views/home.gohtml")
	contactView = views.NewView("bootstrap", "views/contact.gohtml")
	signupView = views.NewView("bootstrap", "views/signup.gohtml")
	r := mux.NewRouter()
	r.HandleFunc("/", home)
	r.HandleFunc("/contact", contact)
	r.HandleFunc("/signup", signup)
	http.ListenAndServe(":3000", r)
}

func home(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	must(homeView.Render(w, nil))

}

func contact(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	must(contactView.Render(w, nil))
}

func signup(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	must(signupView.Render(w, nil))
}

// A helper function that panics on any error
func must(err error) {
	if err != nil {
		panic(err)
	}
}
