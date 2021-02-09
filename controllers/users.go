package controllers

import (
	"fmt"
	"net/http"

	"../views"
)

type SignupForm struct {
	Email    string `schema:"email"`
	Password string `schema:"password"`
	UserName string `schema:"username"`
}

func NewUsers() *Users {
	return &Users{
		NewView: views.NewView("bootstrap", "users/new"),
	}
}

type Users struct {
	NewView *views.View
}

func (u *Users) New(w http.ResponseWriter, r *http.Request) {
	if err := u.NewView.Render(w, nil); err != nil {
		panic(err)
	}
}

func (u *Users) Create(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "This is a temporay user Create.")
	var form SignupForm
	if err := parseForm(r, &form); err != nil {
		panic(err)
	}
	fmt.Fprintln(w, "Email is ", form.Email)
	fmt.Fprintln(w, "password is ", form.Password)
	fmt.Fprintln(w, "user name is ", form.UserName)

}
