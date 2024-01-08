package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// User - A simple user struct
type User struct {
	ID          uint
	Name        string
	Credentials []webauthn.Credential
}

// SessionData - struct to store session data
type SessionData struct {
	UserID      uint
	SessionData *webauthn.SessionData
}

func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"My Organization"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	ipAddresses := []net.IP{net.ParseIP("127.0.0.1")}
	for _, ip := range ipAddresses {
		template.IPAddresses = append(template.IPAddresses, ip)
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	cert := tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}

	return cert, nil
}

// WebAuthnUser - Satisfies the webauthn.User interface
func (u *User) WebAuthnUser() {}

// WebAuthnName - Return the user's display name
func (u *User) WebAuthnName() string {
	return u.Name
}

// WebAuthnDisplayName - Return the user's display name
func (u *User) WebAuthnDisplayName() string {
	return u.Name
}

// WebAuthnIcon - Return the user's icon url
func (u *User) WebAuthnIcon() string {
	return "" // Not implemented
}

// WebAuthnID - Return the user's ID
func (u *User) WebAuthnID() []byte {
	return []byte(fmt.Sprintf("%d", u.ID))
}

// WebAuthnCredentials - Return the user's credentials
func (u *User) WebAuthnCredentials() []webauthn.Credential {
	return u.Credentials
}

var webAuthnConfig *webauthn.WebAuthn
var currentUser User

func init() {
	var err error
	webAuthnConfig, err = webauthn.New(&webauthn.Config{
		RPDisplayName: "My Application",        // Display Name for your site
		RPID:          "localhost",             // Domain name for your site
		RPOrigin:      "http://localhost:8080", // Origin URL for WebAuthn requests
	})
	if err != nil {
		fmt.Printf("Failed to create WebAuthn: %s\n", err)
		return
	}

	// Example user
	currentUser = User{
		ID:   1,
		Name: "testuser",
	}
}

func handleMainPage(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "index.html")
}

func main() {
	cert, err := generateSelfSignedCert()
	if err != nil {
		log.Fatalf("Failed to generate self-signed certificate: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	server := &http.Server{
		Addr:      ":8443",
		TLSConfig: tlsConfig,
	}

	// Register your handlers
	http.HandleFunc("/", handleMainPage)
	http.HandleFunc("/register", handleRegistration)
	http.HandleFunc("/login", handleLogin)

	fmt.Println("Starting HTTPS server on https://localhost:8443")
	log.Fatal(server.ListenAndServeTLS("", ""))

}

func handleRegistration(w http.ResponseWriter, r *http.Request) {
	// Generate registration options
	options, sessionData, err := webAuthnConfig.BeginRegistration(
		&currentUser,
	)
	if err != nil {
		http.Error(w, "Error generating registration data", http.StatusInternalServerError)
		return
	}

	// Store sessionData in a file
	err = storeSessionData(currentUser.ID, sessionData)
	if err != nil {
		http.Error(w, "Error storing session data", http.StatusInternalServerError)
		return
	}

	// Respond with registration options
	json.NewEncoder(w).Encode(options)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	// Generate login options
	options, sessionData, err := webAuthnConfig.BeginLogin(
		&currentUser,
	)
	if err != nil {
		http.Error(w, "Error generating login data", http.StatusInternalServerError)
		return
	}

	// Store sessionData in a file
	err = storeSessionData(currentUser.ID, sessionData)
	if err != nil {
		http.Error(w, "Error storing session data", http.StatusInternalServerError)
		return
	}

	// Respond with login options
	json.NewEncoder(w).Encode(options)
}

func storeSessionData(userID uint, sessionData *webauthn.SessionData) error {
	data := SessionData{
		UserID:      userID,
		SessionData: sessionData,
	}
	fileData, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(fmt.Sprintf("sessiondata_%d.json", userID), fileData, 0644)
}

func retrieveSessionData(userID uint) (*SessionData, error) {
	fileData, err := ioutil.ReadFile(fmt.Sprintf("sessiondata_%d.json", userID))
	if err != nil {
		return nil, err
	}
	var data SessionData
	err = json.Unmarshal(fileData, &data)
	if err != nil {
		return nil, err
	}
	return &data, nil
}
