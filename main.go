package main

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"sync"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/time/rate"
)

// DTO para la solicitud de generación de claves
type KeyRequest struct {
	Passphrase string `json:"passphrase"` // Opcional
}

// DTO para la respuesta de claves
type KeyResponse struct {
	PublicKey  string `json:"publicKey"`
	PrivateKey string `json:"privateKey"`
}

type EncryptRequest struct {
	PublicKey string `json:"publicKey"` // Llave pública en formato PEM
	Content   string `json:"content"`   // Texto plano a cifrar
}

type EncryptResponse struct {
	EncryptedContent string `json:"encryptedContent"` // Contenido cifrado en Base64
}

type DecryptRequest struct {
	PrivateKey string `json:"privateKey"`
	Passphrase string `json:"passphrase"` // Contraseña de la clave privada
	Content    string `json:"content"`
}

type DecryptResponse struct {
	DecryptedContent string `json:"decryptedContent"`
}

type SignRequest struct {
	PrivateKey string `json:"privateKey"`
	Passphrase string `json:"passphrase"` // Contraseña de la clave privada
	Content    string `json:"content"`    // Contenido a firmar
}
type SignResponse struct {
	Signature string `json:"signature"` // Firma en Base64
}

type VerifyRequest struct {
	PublicKey string `json:"publicKey"`
	Content   string `json:"content"`   // Contenido original
	Signature string `json:"signature"` // Firma en Base64
}
type VerifyResponse struct {
	IsValid bool `json:"isValid"`
}

// --- Lógica de Criptografía Asimétrica (RSA) ---

func generateRSAKeys(passphrase []byte) (string, string, error) {
	// 1. Generar la clave privada RSA (ej. 2048 bits)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}

	var privateKeyPEM []byte
	der := x509.MarshalPKCS1PrivateKey(privateKey) // Datos DER de la clave

	if passphrase != nil {
		// Encriptar la clave privada con PBKDF2 + AES-GCM (reemplazo de EncryptPEMBlock)
		encPEM, err := encryptPrivateKeyPEM(der, passphrase)
		if err != nil {
			return "", "", err
		}
		privateKeyPEM = encPEM
	} else {
		// Clave privada sin encriptar
		privateKeyPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: der,
		})
	}

	// 3. Generar y codificar la Clave Pública
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", "", err
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return string(publicKeyPEM), string(privateKeyPEM), nil
}

// encryptWithPublicKey (Cifra contenido usando RSA-OAEP)
func encryptWithPublicKey(content []byte, publicKeyPEM string) (string, error) {
	// 1. Decodificar el bloque PEM de la llave pública
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return "", errors.New("failed to parse PEM block containing the public key")
	}

	// 2. Parsear la llave pública
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return "", errors.New("not an RSA public key")
	}

	// 3. Cifrar usando RSA-OAEP (más seguro que PKCS1v15)
	encryptedBytes, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPub, content, nil)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt: %w", err)
	}

	// 4. Devolver como Base64
	return base64.StdEncoding.EncodeToString(encryptedBytes), nil
}

const kdfIter = 100000

// encryptPrivateKeyPEM encripta la DER de la clave privada usando PBKDF2 + AES-GCM
func encryptPrivateKeyPEM(der []byte, passphrase []byte) ([]byte, error) {
	// 1. Generar Salt
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	// 2. Derivar Clave de Cifrado (KDF)
	key := pbkdf2.Key(passphrase, salt, kdfIter, 32, sha256.New) // Clave de 32 bytes (AES-256)

	// 3. Cifrado AES-GCM
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, der, nil)

	// 4. Almacenar metadatos en los Headers PEM (PKCS#8 style)
	pemBlock := &pem.Block{
		Type: "ENCRYPTED PRIVATE KEY",
		Headers: map[string]string{
			"Salt":    base64.StdEncoding.EncodeToString(salt),
			"Nonce":   base64.StdEncoding.EncodeToString(nonce),
			"KdfIter": strconv.Itoa(kdfIter),
		},
		Bytes: ciphertext,
	}

	return pem.EncodeToMemory(pemBlock), nil
}

// decryptPrivateKeyPEM desencripta un bloque PEM creado por encryptPrivateKeyPEM
func decryptPrivateKeyPEM(block *pem.Block, passphrase []byte) ([]byte, error) {
	// 1. Extraer metadatos de los Headers PEM
	saltB64, ok1 := block.Headers["Salt"]
	nonceB64, ok2 := block.Headers["Nonce"]
	iterStr, ok3 := block.Headers["KdfIter"]
	if !ok1 || !ok2 || !ok3 {
		return nil, errors.New("missing encryption metadata in PEM headers")
	}

	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		return nil, err
	}
	nonce, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil {
		return nil, err
	}
	iter, err := strconv.Atoi(iterStr)
	if err != nil {
		return nil, err
	}

	// 2. Derivar Clave de Descifrado
	key := pbkdf2.Key(passphrase, salt, iter, 32, sha256.New)

	// 3. Descifrado AES-GCM
	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, err
	}

	plaintext, err := gcm.Open(nil, nonce, block.Bytes, nil)
	if err != nil {
		// La contraseña es incorrecta o los datos están corruptos
		return nil, errors.New("failed to decrypt key (check passphrase)")
	}

	return plaintext, nil
}

// decryptWithPrivateKey (Descifra contenido usando RSA-OAEP)
func decryptWithPrivateKey(encryptedContent string, privateKeyPEM string, passphrase []byte) (string, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return "", errors.New("failed to parse PEM block")
	}

	var decryptedKeyBytes []byte
	var err error

	// CRÍTICO: Chequeamos el tipo de bloque
	switch block.Type {
	case "ENCRYPTED PRIVATE KEY":
		if passphrase == nil {
			return "", errors.New("passphrase required but not provided")
		}
		decryptedKeyBytes, err = decryptPrivateKeyPEM(block, passphrase)
		if err != nil {
			return "", fmt.Errorf("failed to decrypt PEM block: %w", err)
		}
	case "RSA PRIVATE KEY":
		decryptedKeyBytes = block.Bytes
	default:
		return "", errors.New("unsupported private key type")
	}
	// 3. Parsear la llave privada
	privateKey, err := x509.ParsePKCS1PrivateKey(decryptedKeyBytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %w", err)
	}

	// 4. Decodificar el contenido cifrado de Base64
	encryptedBytes, err := base64.StdEncoding.DecodeString(encryptedContent)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64 content: %w", err)
	}
	// 5. Descifrar usando RSA-OAEP
	decryptedBytes, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, encryptedBytes, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt content: %w", err)
	}

	// 6. Devolver el contenido descifrado como string
	return string(decryptedBytes), nil
}

func signContent(privateKeyPEM string, passphrase []byte, content string) (string, error) {
	// 1. Decodificar y descifrar el bloque PEM (Reutilizamos tu lógica)
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return "", errors.New("failed to parse PEM block")
	}

	var decryptedKeyBytes []byte
	var err error
	if block.Type == "ENCRYPTED PRIVATE KEY" {
		decryptedKeyBytes, err = decryptPrivateKeyPEM(block, passphrase)
		if err != nil {
			return "", fmt.Errorf("failed to decrypt PEM block: %w", err)
		}
	} else {
		decryptedKeyBytes = block.Bytes
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(decryptedKeyBytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %w", err)
	}

	// 2. Hashear el contenido (SHA-256)
	hashed := sha256.Sum256([]byte(content))

	// 3. Firmar el hash usando RSA-PSS
	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, hashed[:], nil)
	if err != nil {
		return "", fmt.Errorf("failed to sign: %w", err)
	}

	// 4. Devolver la firma como Base64
	return base64.StdEncoding.EncodeToString(signature), nil
}

// verifySignature (Verifica la firma usando la clave pública)
func verifySignature(publicKeyPEM string, content string, signatureB64 string) (bool, error) {
	// 1. Parsear la clave pública PEM
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return false, errors.New("failed to parse PEM block containing the public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return false, fmt.Errorf("failed to parse public key: %w", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return false, errors.New("not an RSA public key")
	}

	// 2. Decodificar la firma (Base64)
	signature, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return false, fmt.Errorf("failed to decode base64 signature: %w", err)
	}

	// 3. Hashear el contenido original
	hashed := sha256.Sum256([]byte(content))

	// 4. Verificar la firma PSS
	err = rsa.VerifyPSS(rsaPub, crypto.SHA256, hashed[:], signature, nil)
	if err != nil {
		// Si 'err' no es nulo, la firma es inválida
		log.Printf("Verification failed: %v", err)
		return false, nil
	}

	// La firma es válida
	return true, nil
}

// --- Handlers HTTP ---

func generateKeysHandler(w http.ResponseWriter, r *http.Request) {
	// Decodificar el JSON del frontend
	var req KeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	var passphrase []byte
	if req.Passphrase != "" {
		passphrase = []byte(req.Passphrase)
	}

	// Generar las claves
	pubKey, privKey, err := generateRSAKeys(passphrase)
	if err != nil {
		http.Error(w, "Failed to generate keys", http.StatusInternalServerError)
		return
	}

	// Devolver las claves como JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(KeyResponse{
		PublicKey:  pubKey,
		PrivateKey: privKey,
	})
}

func encryptHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req EncryptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	// Cifrar el contenido
	encryptedContent, err := encryptWithPublicKey([]byte(req.Content), req.PublicKey)
	if err != nil {
		log.Printf("Error during encryption: %v", err)
		http.Error(w, "Encryption failed. Ensure the public key is valid PEM format.", http.StatusInternalServerError)
		return
	}

	// Devolver el contenido cifrado
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(EncryptResponse{
		EncryptedContent: encryptedContent,
	})
}

func decryptHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req DecryptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}
	// Descifrar el contenido
	decryptedContent, err := decryptWithPrivateKey(req.Content, req.PrivateKey, []byte(req.Passphrase))
	if err != nil {
		log.Printf("Error during decryption: %v", err)
		http.Error(w, "Decryption failed. Ensure the private key and passphrase are correct.", http.StatusInternalServerError)
		return
	}
	// Devolver el contenido descifrado
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(DecryptResponse{
		DecryptedContent: decryptedContent,
	})
}

// 4. Endpoint: /asymmetric/sign
func signHandler(w http.ResponseWriter, r *http.Request) {
	var req SignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	signature, err := signContent(req.PrivateKey, []byte(req.Passphrase), req.Content)
	if err != nil {
		log.Printf("Error during signing: %v", err)
		http.Error(w, "Signing failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(SignResponse{
		Signature: signature,
	})
}

// 5. Endpoint: /asymmetric/verify
func verifyHandler(w http.ResponseWriter, r *http.Request) {
	var req VerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	isValid, err := verifySignature(req.PublicKey, req.Content, req.Signature)
	if err != nil {
		log.Printf("Error during verification: %v", err)
		http.Error(w, "Verification failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(VerifyResponse{
		IsValid: isValid,
	})
}

// --- Middleware CORS ---
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Origen del frontend (Firebase Hosting)
		clientURL := os.Getenv("CLIENT_PROD_URL")

		w.Header().Set("Access-Control-Allow-Origin", clientURL)
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		w.Header().Set("Access-Control-Allow-Credentials", "true")
		
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Almacén de limitadores por IP
var (
	clients = make(map[string]*rate.Limiter)
	mu      sync.Mutex
)

// getLimiter (Crea un limitador por IP: 10 peticiones por minuto)
func getLimiter(ip string) *rate.Limiter {
	mu.Lock()
	defer mu.Unlock()

	limiter, exists := clients[ip]
	if !exists {
		// Permite 10 eventos por minuto (1 evento cada 6 segundos)
		limiter = rate.NewLimiter(rate.Every(6*time.Second), 10)
		clients[ip] = limiter
	}
	return limiter
}

// rateLimitMiddleware (Middleware para limitar peticiones)
func rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Obtener la IP real (importante detrás de Caddy/Proxy)
		ip := r.Header.Get("X-Forwarded-For")
		if ip == "" {
			ip = r.RemoteAddr
		}

		limiter := getLimiter(ip)

		if !limiter.Allow() {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			log.Printf("Rate limit exceeded for IP: %s", ip)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// --- Servidor Principal ---

func main() {
	// Definimos un enrutador (mux)
	mux := http.NewServeMux()

	// Arquitectura escalable
	mux.Handle("/asymmetric/generate-keys", http.HandlerFunc(generateKeysHandler))
	mux.Handle("/asymmetric/encrypt", http.HandlerFunc(encryptHandler))
	mux.Handle("/asymmetric/decrypt", http.HandlerFunc(decryptHandler))
	mux.Handle("/asymmetric/sign", http.HandlerFunc(signHandler))
	mux.Handle("/asymmetric/verify", http.HandlerFunc(verifyHandler))

	handler := corsMiddleware(rateLimitMiddleware(mux))

	const port = "8081" // Puerto interno de Go
	log.Printf("Iniciando CryptoService (Go) en http://localhost:%s", port)

	if err := http.ListenAndServe(":"+port, handler); err != nil {
		log.Fatal(err)
	}
}
