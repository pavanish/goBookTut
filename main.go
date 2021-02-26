package main

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"

	"./controllers"

	"./models"
	"./views"
)

var (
	homeView    *views.View
	contactView *views.View
	//signupView  *views.View
)

const (
	host     = "localhost"
	port     = 5432
	user     = "postgres"
	password = "password"
	dbname   = "scientipic_dev"
)

//var homeTemplate *template.Template
//var contactTemplate *template.Template

func main() {

	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s "+
		"password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname)

	us, err := models.NewUserService(psqlInfo)
	if err != nil {
		panic(err)
	}
	defer us.Close()

	//us.DestructiveReset()
	us.AutoMigrate()
	//homeView = views.NewView("bootstrap", "views/home.gohtml")
	//contactView = views.NewView("bootstrap", "views/contact.gohtml")
	//signupView = views.NewView("bootstrap", "views/signup.gohtml")
	staticC := controllers.NewStatic()
	usersC := controllers.NewUsers(us)
	r := mux.NewRouter()
	r.Handle("/", staticC.Home).Methods("GET")
	r.Handle("/contact", staticC.Contact).Methods("GET")
	r.HandleFunc("/signup", usersC.New).Methods("GET")
	r.HandleFunc("/signup", usersC.Create).Methods("POST")
	r.Handle("/login", usersC.LoginView).Methods("GET")
	r.HandleFunc("/login", usersC.Login).Methods("POST")
	r.HandleFunc("/cookietest", usersC.CookieTest).Methods("GET")
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

// func signup(w http.ResponseWriter, r *http.Request) {
// 	w.Header().Set("Content-Type", "text/html")
// 	must(signupView.Render(w, nil))
// }

// A helper function that panics on any error
func must(err error) {
	if err != nil {
		panic(err)
	}
}
