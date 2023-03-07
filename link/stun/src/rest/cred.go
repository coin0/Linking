package rest

import (
	"net/http"
	"io"
)

func handleCredentialSettings(w http.ResponseWriter, req *http.Request) {

	io.WriteString(w, "handleCredentialSettings")
}

func handleCredentialSettingsCleanuptime(w http.ResponseWriter, req *http.Request) {

	io.WriteString(w, "handleCredentialSettingsCleanuptime")
}

func handleCredentialSettingsMaxusers(w http.ResponseWriter, req *http.Request) {

	io.WriteString(w, "handleCredentialSettingsMaxusers")
}

func handleCredentialUser(w http.ResponseWriter, req *http.Request) {

	io.WriteString(w, "handleCredentialUser")
}

func handleCredentialUserPassword(w http.ResponseWriter, req *http.Request) {

	io.WriteString(w, "handleCredentialUserPassword")
}

func handleCredentialUserExpiry(w http.ResponseWriter, req *http.Request) {

	io.WriteString(w, "handleCredentialUserExpiry")
}

func handleCredentialUserEnable(w http.ResponseWriter, req *http.Request) {

	io.WriteString(w, "handleCredentialUserEnable")
}

func handleCredentialUserDisable(w http.ResponseWriter, req *http.Request) {

	io.WriteString(w, "handleCredentialUserDisable")
}
