package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

var host string
var port string

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

func generateSelfSignedCert(host string) (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"My Organization"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	} else {
		template.DNSNames = append(template.DNSNames, host)
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

	flag.StringVar(&host, "host", "localhost", "Hostname or IP to listen on")
	flag.StringVar(&port, "port", "8443", "Port to listen on")
	flag.Parse()

	var err error
	webAuthnConfig, err = webauthn.New(&webauthn.Config{
		RPDisplayName: "Demo PoC for Passkeys",        // Display Name for your site
		RPID:          host,                           // Domain name for your site
		RPOrigin:      "https://" + host + ":" + port, // Origin URL for WebAuthn requests
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
	cert, err := generateSelfSignedCert(host)
	if err != nil {
		log.Fatalf("Failed to generate self-signed certificate: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	server := &http.Server{
		Addr:      "0.0.0.0:" + port,
		TLSConfig: tlsConfig,
	}
	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/", fs)

	// Register your handlers
	// http.HandleFunc("/", handleMainPage)
	http.HandleFunc("/register", handleRegistration)
	http.HandleFunc("/login", handleLogin)

	// Create a TLS listener
	listener, err := tls.Listen("tcp", server.Addr, tlsConfig)
	if err != nil {
		log.Fatalf("Failed to listen on %s:%s - %v", host, port, err)
	}

	fmt.Printf("Starting HTTPS server on https://%s:%s\n", host, port)
	log.Fatal(server.Serve(listener)) // Use Serve, not ListenAndServeTL

}

func handleRegistration(w http.ResponseWriter, r *http.Request) {
	// Generate registration options
	options, sessionData, err := webAuthnConfig.BeginRegistration(
		&currentUser,
	)
	if err != nil {
		log.Printf("ERROR: %v", err)
		http.Error(w, "Error generating registration data", http.StatusInternalServerError)
		return
	}

	// Store sessionData in a file
	err = storeSessionData(currentUser.ID, sessionData)
	if err != nil {
		log.Printf("ERROR: %v", err)
		http.Error(w, "Error storing session data", http.StatusInternalServerError)
		return
	}

	// Respond with registration options
	err = json.NewEncoder(w).Encode(options)
	if err != nil {
		log.Printf("ERROR: %v", err)
	}
	log.Printf("User %v registered with credentials: %+v", currentUser.ID, currentUser.Credentials)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	log.Println("Login request received for user:", currentUser.ID)

	if len(currentUser.Credentials) == 0 {
		log.Printf("No credentials found for user %v", currentUser.ID)
		http.Error(w, "No credentials found for user", http.StatusInternalServerError)
		return
	}

	// Generate login options
	options, sessionData, err := webAuthnConfig.BeginLogin(
		&currentUser,
	)
	if err != nil {
		log.Printf("Error generating login data: %v", err)
		http.Error(w, "Error generating login data", http.StatusInternalServerError)
		return
	}

	log.Printf("Generated login options: %+v", options)
	log.Printf("Generated session data: %+v", sessionData)

	// Store sessionData in a file
	err = storeSessionData(currentUser.ID, sessionData)
	if err != nil {
		log.Printf("Error storing session data: %v", err)
		http.Error(w, "Error storing session data", http.StatusInternalServerError)
		return
	}

	// Respond with login options
	err = json.NewEncoder(w).Encode(options)
	if err != nil {
		log.Printf("Error encoding response: %v", err)
		http.Error(w, "Error encoding response", http.StatusInternalServerError)
	}

	log.Println("Login response sent")

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
