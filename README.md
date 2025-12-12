# 🔐 Crypto Service

A high-performance cryptographic microservice built with Go that provides asymmetric encryption, decryption, digital signatures, and signature verification capabilities through a RESTful API.

[![Live Demo](https://img.shields.io/badge/demo-live-brightgreen)](https://devcybsec.com/en/crypto)
[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go)](https://golang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## 🌟 Features

- **🔑 Key Generation**: Generate secure PGP/GPG key pairs with passphrase protection
- **🔒 Asymmetric Encryption**: Encrypt content using public keys
- **🔓 Secure Decryption**: Decrypt content using private keys with passphrase authentication
- **✍️ Digital Signatures**: Sign content to verify authenticity and integrity
- **✅ Signature Verification**: Verify digital signatures to ensure data hasn’t been tampered with
- **🚀 High Performance**: Built with Go for maximum speed and efficiency
- **🌐 CORS Enabled**: Ready for cross-origin requests from web applications
- **📱 Production Ready**: Deployed and tested at [devcybsec.com/crypto](https://devcybsec.com/en/
## 🛠️ Technologies

### Backend

- **Go 1.21+**
- **ProtonMail GopenPGP**: Industry-standard PGP implementation
- **Gorilla Mux**: HTTP router and dispatcher
- **CORS Middleware**: Cross-origin resource sharing 

## 📋 API Endpoints

### Endpoints

#### 1. Generate Keys

Generate a new PGP key pair.

**Endpoint**: `POST /asymmetric/generate-keys`

**Request Body**:

```json
{
  "passphrase": "your-secure-passphrase"
}
```

**Response**:

```json
{
  "publicKey": "-----BEGIN PGP PUBLIC KEY BLOCK-----\n...",
  "privateKey": "-----BEGIN PGP PRIVATE KEY BLOCK-----\n..."
}
```

#### 2. Encrypt Content

Encrypt content using a public key.

**Endpoint**: `POST /asymmetric/encrypt`

**Request Body**:

```json
{
  "publicKey": "-----BEGIN PGP PUBLIC KEY BLOCK-----\n...",
  "content": "Secret message to encrypt"
}
```

**Response**:

```json
{
  "encryptedContent": "-----BEGIN PGP MESSAGE-----\n..."
}
```

#### 3. Decrypt Content

Decrypt content using a private key and passphrase.

**Endpoint**: `POST /asymmetric/decrypt`

**Request Body**:

```json
{
  "privateKey": "-----BEGIN PGP PRIVATE KEY BLOCK-----\n...",
  "passphrase": "your-secure-passphrase",
  "content": "-----BEGIN PGP MESSAGE-----\n..."
}
```

**Response**:

```json
{
  "decryptedContent": "Original secret message"
}
```

#### 4. Sign Content

Create a digital signature for content.

**Endpoint**: `POST /asymmetric/sign`

**Request Body**:

```json
{
  "privateKey": "-----BEGIN PGP PRIVATE KEY BLOCK-----\n...",
  "passphrase": "your-secure-passphrase",
  "content": "Message to sign"
}
```

**Response**:

```json
{
  "signature": "-----BEGIN PGP SIGNATURE-----\n..."
}
```

#### 5. Verify Signature

Verify a digital signature.

**Endpoint**: `POST /asymmetric/verify`

**Request Body**:

```json
{
  "publicKey": "-----BEGIN PGP PUBLIC KEY BLOCK-----\n...",
  "content": "Original message",
  "signature": "-----BEGIN PGP SIGNATURE-----\n..."
}
```

**Response**:

```json
{
  "isValid": true
}
```

## 🚀 Getting Started

### Prerequisites

- Go 1.21 or higher
- Git

### Installation

1. **Clone the repository**:

```bash
git clone https://github.com/DevCybSec/crypto-service.git
cd crypto-service
```

1. **Install dependencies**:

```bash
go mod download
```

1. **Set up environment variables**:
   Create a `.env` file in the root directory:

```env
# Server Configuration
PORT=8080
HOST=localhost

# CORS Configuration
ALLOWED_ORIGINS=http://localhost:3000,https://devcybsec.com

# Optional: Add other configuration as needed
```

1. **Run the service**:

```bash
go run main.go
```

The service will start on `http://localhost:8080`

### Docker Deployment (Optional)

```bash
# Build the Docker image
docker build -t crypto-service .

# Run the container
docker run -p 8080:8080 --env-file .env crypto-service
```

## 💻 Usage Example

### Using cURL

```bash
# Generate keys
curl -X POST http://localhost:8080/asymmetric/generate-keys \
  -H "Content-Type: application/json" \
  -d '{"passphrase":"mySecurePass123"}'

# Encrypt content
curl -X POST http://localhost:8080/asymmetric/encrypt \
  -H "Content-Type: application/json" \
  -d '{
    "publicKey":"-----BEGIN PGP PUBLIC KEY BLOCK-----\n...",
    "content":"Hello, World!"
  }'
```

### Using JavaScript/TypeScript

```typescript
const response = await fetch('http://localhost:8080/asymmetric/generate-keys', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({
    passphrase: 'mySecurePass123'
  })
});

const { publicKey, privateKey } = await response.json();
```

## 🔒 Security Considerations

- **Never expose private keys**: Keep private keys secure and never transmit them over unsecured channels
- **Use strong passphrases**: Always use strong, unique passphrases for key generation
- **HTTPS in Production**: Always use HTTPS in production environments
- **Rate Limiting**: Implement rate limiting to prevent abuse
- **Input Validation**: The service validates all inputs, but additional client-side validation is recommended
- **Key Management**: Implement proper key rotation and management policies

## 📁 Project Structure

```
crypto-service/
├── main.go              # Application entry point
├── handlers/            # HTTP request handlers
├── crypto/              # Cryptographic operations
├── middleware/          # CORS and other middleware
├── models/              # Request/Response models
├── utils/               # Utility functions
├── go.mod               # Go module dependencies
├── go.sum               # Dependency checksums
├── Dockerfile           # Docker configuration
├── .env.example         # Environment variables template
└── README.md            # This file
```

## 🧪 Testing

```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run tests with verbose output
go test -v ./...
```

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
1. Create a feature branch (`git checkout -b feature/amazing-feature`)
1. Commit your changes (`git commit -m 'Add some amazing feature'`)
1. Push to the branch (`git push origin feature/amazing-feature`)
1. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the <LICENSE> file for details.

## 👤 Author

**Edgar (Homz) Macias**

- Website: [edgarmacias.com](https://edgarmacias.com)
- GitHub: [@edgar-macias-se](https://github.com/edgat-macias-se)

## 🙏 Acknowledgments

- [ProtonMail GopenPGP](https://github.com/ProtonMail/gopenpgp) for the excellent PGP implementation
- The Go community for amazing tools and libraries
- All contributors who help improve this project

## 📞 Support

If you have any questions or issues, please:

1. Check the [Issues](https://github.com/DevCybSec/crypto-service/issues) page
1. Open a new issue if your problem isn’t already listed
1. Visit the [live demo](https://devcybsec.com/en/crypto) to see it in action

-----

**⭐ If you find this project useful, please consider giving it a star!**
