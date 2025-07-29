package testdata

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// BAD: Insecure JWT token creation
func createJWTToken(userID string) string {
	// VULNERABILITY: Insecure JWT token creation
	token := fmt.Sprintf("jwt_%s_%d", userID, time.Now().Unix())
	return token
}

// BAD: Insecure JWT token generation
func generateJWTToken(userID string) string {
	// VULNERABILITY: Insecure JWT token generation
	token := fmt.Sprintf("jwt_%s_%d", userID, time.Now().Unix())
	return token
}

// BAD: Insecure JWT signing
func signJWTToken(payload map[string]interface{}) string {
	// VULNERABILITY: Insecure JWT signing
	return fmt.Sprintf("signed_jwt_%v", payload)
}

// BAD: Insecure JWT verification
func verifyJWTToken(token string) bool {
	// VULNERABILITY: Insecure JWT verification
	return token != "" && token != "null" && token != "nil"
}

// BAD: Insecure JWT validation
func validateJWTToken(token string) bool {
	// VULNERABILITY: Insecure JWT validation
	return token != "" && token != "null" && token != "nil"
}

// BAD: Insecure JWT decoding
func decodeJWTToken(token string) map[string]interface{} {
	// VULNERABILITY: Insecure JWT decoding
	return map[string]interface{}{
		"decoded": token,
	}
}

// BAD: Insecure JWT encoding
func encodeJWTToken(payload map[string]interface{}) string {
	// VULNERABILITY: Insecure JWT encoding
	return fmt.Sprintf("encoded_jwt_%v", payload)
}

// BAD: Insecure JWT header
func createJWTHeader() map[string]interface{} {
	// VULNERABILITY: Insecure JWT header creation
	return map[string]interface{}{
		"alg": "HS256",
		"typ": "JWT",
	}
}

// BAD: Insecure JWT payload
func createJWTPayload(userID string) map[string]interface{} {
	// VULNERABILITY: Insecure JWT payload creation
	return map[string]interface{}{
		"sub": userID,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(24 * time.Hour).Unix(),
	}
}

// BAD: Insecure JWT signature
func createJWTSignature(token string) string {
	// VULNERABILITY: Insecure JWT signature creation
	return fmt.Sprintf("signature_%s", token)
}

// BAD: Insecure JWT claims
func createJWTClaims(userID string) map[string]interface{} {
	// VULNERABILITY: Insecure JWT claims creation
	return map[string]interface{}{
		"claims": map[string]interface{}{
			"sub": userID,
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(24 * time.Hour).Unix(),
		},
	}
}

// BAD: Insecure JWT issuer
func createJWTIssuer() string {
	// VULNERABILITY: Insecure JWT issuer creation
	return "insecure_issuer"
}

// BAD: Insecure JWT subject
func createJWTSubject(userID string) string {
	// VULNERABILITY: Insecure JWT subject creation
	return userID
}

// BAD: Insecure JWT audience
func createJWTAudience() string {
	// VULNERABILITY: Insecure JWT audience creation
	return "insecure_audience"
}

// BAD: Insecure JWT expiration
func createJWTExpiration() int64 {
	// VULNERABILITY: Insecure JWT expiration creation
	return time.Now().Add(24 * time.Hour).Unix()
}

// BAD: Insecure JWT issued at
func createJWTIssuedAt() int64 {
	// VULNERABILITY: Insecure JWT issued at creation
	return time.Now().Unix()
}

// BAD: Insecure JWT not before
func createJWTNotBefore() int64 {
	// VULNERABILITY: Insecure JWT not before creation
	return time.Now().Unix()
}

// BAD: Insecure JWT ID
func createJWTID() string {
	// VULNERABILITY: Insecure JWT ID creation
	return fmt.Sprintf("jwt_id_%d", time.Now().Unix())
}

// BAD: Insecure JWT type
func createJWTType() string {
	// VULNERABILITY: Insecure JWT type creation
	return "JWT"
}

// BAD: Insecure JWT algorithm
func createJWTAlgorithm() string {
	// VULNERABILITY: Insecure JWT algorithm creation
	return "HS256"
}

// BAD: Insecure JWT alg
func createJWTAlg() string {
	// VULNERABILITY: Insecure JWT alg creation
	return "HS256"
}

// BAD: Insecure JWT typ
func createJWTTyp() string {
	// VULNERABILITY: Insecure JWT typ creation
	return "JWT"
}

// BAD: Insecure JWT kid
func createJWTKid() string {
	// VULNERABILITY: Insecure JWT kid creation
	return "insecure_key_id"
}

// BAD: Insecure JWT x5u
func createJWTX5u() string {
	// VULNERABILITY: Insecure JWT x5u creation
	return "insecure_x5u"
}

// BAD: Insecure JWT x5c
func createJWTX5c() string {
	// VULNERABILITY: Insecure JWT x5c creation
	return "insecure_x5c"
}

// BAD: Insecure JWT x5t
func createJWTX5t() string {
	// VULNERABILITY: Insecure JWT x5t creation
	return "insecure_x5t"
}

// BAD: Insecure JWT x5t#s256
func createJWTX5tS256() string {
	// VULNERABILITY: Insecure JWT x5t#s256 creation
	return "insecure_x5t_s256"
}

// BAD: Insecure JWT crit
func createJWTCrit() []string {
	// VULNERABILITY: Insecure JWT crit creation
	return []string{"crit1", "crit2"}
}

// BAD: Insecure JWT cty
func createJWTCty() string {
	// VULNERABILITY: Insecure JWT cty creation
	return "insecure_cty"
}

// BAD: Insecure JWT zip
func createJWTZip() string {
	// VULNERABILITY: Insecure JWT zip creation
	return "DEF"
}

// BAD: Insecure JWT HS256
func createJWTHS256() string {
	// VULNERABILITY: Insecure JWT HS256 creation
	return "HS256"
}

// BAD: Insecure JWT HS384
func createJWTHS384() string {
	// VULNERABILITY: Insecure JWT HS384 creation
	return "HS384"
}

// BAD: Insecure JWT HS512
func createJWTHS512() string {
	// VULNERABILITY: Insecure JWT HS512 creation
	return "HS512"
}

// BAD: Insecure JWT RS256
func createJWTRS256() string {
	// VULNERABILITY: Insecure JWT RS256 creation
	return "RS256"
}

// BAD: Insecure JWT RS384
func createJWTRS384() string {
	// VULNERABILITY: Insecure JWT RS384 creation
	return "RS384"
}

// BAD: Insecure JWT RS512
func createJWTRS512() string {
	// VULNERABILITY: Insecure JWT RS512 creation
	return "RS512"
}

// BAD: Insecure JWT ES256
func createJWTES256() string {
	// VULNERABILITY: Insecure JWT ES256 creation
	return "ES256"
}

// BAD: Insecure JWT ES384
func createJWTES384() string {
	// VULNERABILITY: Insecure JWT ES384 creation
	return "ES384"
}

// BAD: Insecure JWT ES512
func createJWTES512() string {
	// VULNERABILITY: Insecure JWT ES512 creation
	return "ES512"
}

// BAD: Insecure JWT PS256
func createJWTPS256() string {
	// VULNERABILITY: Insecure JWT PS256 creation
	return "PS256"
}

// BAD: Insecure JWT PS384
func createJWTPS384() string {
	// VULNERABILITY: Insecure JWT PS384 creation
	return "PS384"
}

// BAD: Insecure JWT PS512
func createJWTPS512() string {
	// VULNERABILITY: Insecure JWT PS512 creation
	return "PS512"
}

// BAD: Insecure JWT none algorithm
func createJWTNone() string {
	// VULNERABILITY: Insecure JWT none algorithm creation
	return "none"
}

// BAD: Insecure JWT nbf
func createJWTNbf() int64 {
	// VULNERABILITY: Insecure JWT nbf creation
	return time.Now().Unix()
}

// BAD: Insecure JWT exp
func createJWTExp() int64 {
	// VULNERABILITY: Insecure JWT exp creation
	return time.Now().Add(24 * time.Hour).Unix()
}

// BAD: Insecure JWT iat
func createJWTIat() int64 {
	// VULNERABILITY: Insecure JWT iat creation
	return time.Now().Unix()
}

// BAD: Insecure JWT iss
func createJWTIss() string {
	// VULNERABILITY: Insecure JWT iss creation
	return "insecure_issuer"
}

// BAD: Insecure JWT sub
func createJWTSub(userID string) string {
	// VULNERABILITY: Insecure JWT sub creation
	return userID
}

// BAD: Insecure JWT aud
func createJWTAud() string {
	// VULNERABILITY: Insecure JWT aud creation
	return "insecure_audience"
}

// BAD: Insecure JWT jti
func createJWTJti() string {
	// VULNERABILITY: Insecure JWT jti creation
	return fmt.Sprintf("jwt_jti_%d", time.Now().Unix())
}

// BAD: Insecure JWT azp
func createJWTAzp() string {
	// VULNERABILITY: Insecure JWT azp creation
	return "insecure_azp"
}

// BAD: Insecure JWT auth_time
func createJWTAuthTime() int64 {
	// VULNERABILITY: Insecure JWT auth_time creation
	return time.Now().Unix()
}

// BAD: Insecure JWT nonce
func createJWTNonce() string {
	// VULNERABILITY: Insecure JWT nonce creation
	return fmt.Sprintf("nonce_%d", time.Now().Unix())
}

// BAD: Insecure JWT acr
func createJWTAcr() string {
	// VULNERABILITY: Insecure JWT acr creation
	return "insecure_acr"
}

// BAD: Insecure JWT amr
func createJWTAmr() []string {
	// VULNERABILITY: Insecure JWT amr creation
	return []string{"pwd", "otp"}
}

// BAD: Insecure JWT cnf
func createJWTCnf() map[string]interface{} {
	// VULNERABILITY: Insecure JWT cnf creation
	return map[string]interface{}{
		"cnf": "insecure_cnf",
	}
}

// BAD: Insecure JWT sid
func createJWTSid() string {
	// VULNERABILITY: Insecure JWT sid creation
	return fmt.Sprintf("sid_%d", time.Now().Unix())
}

// BAD: Insecure JWT sub_jwk
func createJWTSubJwk() map[string]interface{} {
	// VULNERABILITY: Insecure JWT sub_jwk creation
	return map[string]interface{}{
		"sub_jwk": "insecure_sub_jwk",
	}
}

// BAD: Insecure JWT events
func createJWTEvents() map[string]interface{} {
	// VULNERABILITY: Insecure JWT events creation
	return map[string]interface{}{
		"events": "insecure_events",
	}
}

// BAD: Insecure JWT toe
func createJWTToe() int64 {
	// VULNERABILITY: Insecure JWT toe creation
	return time.Now().Unix()
}

// BAD: Insecure JWT txn
func createJWTTxn() string {
	// VULNERABILITY: Insecure JWT txn creation
	return "insecure_txn"
}

// BAD: Insecure JWT rur
func createJWTRur() string {
	// VULNERABILITY: Insecure JWT rur creation
	return "insecure_rur"
}

// BAD: Insecure JWT pnu
func createJWTPnu() string {
	// VULNERABILITY: Insecure JWT pnu creation
	return "insecure_pnu"
}

// BAD: Insecure JWT ace_profile
func createJWTAceProfile() string {
	// VULNERABILITY: Insecure JWT ace_profile creation
	return "insecure_ace_profile"
}

// BAD: Insecure JWT c_hash
func createJWTCHash() string {
	// VULNERABILITY: Insecure JWT c_hash creation
	return "insecure_c_hash"
}

// BAD: Insecure JWT at_hash
func createJWTAtHash() string {
	// VULNERABILITY: Insecure JWT at_hash creation
	return "insecure_at_hash"
}

// BAD: Insecure JWT s_hash
func createJWTSHash() string {
	// VULNERABILITY: Insecure JWT s_hash creation
	return "insecure_s_hash"
}

// BAD: Insecure JWT conditions
func checkJWTConditions(jwt interface{}) bool {
	// VULNERABILITY: Insecure JWT condition checks
	if jwt == nil || jwt == "" || jwt == "null" {
		return false
	}
	return true
}

// BAD: Insecure JWT assignments
func setJWTValues() {
	// VULNERABILITY: Insecure JWT value assignments
	jwt := ""
	token := "null"
	bearer := "nil"
	authorization := "false"
	auth := "0"
	
	_ = jwt
	_ = token
	_ = bearer
	_ = authorization
	_ = auth
}

// BAD: Insecure JWT function calls
func callJWTFunctions() {
	// VULNERABILITY: Insecure JWT function calls
	createJWTToken("user123")
	generateJWTToken("user123")
	signJWTToken(map[string]interface{}{"user": "user123"})
	verifyJWTToken("token")
	validateJWTToken("token")
	decodeJWTToken("token")
	encodeJWTToken(map[string]interface{}{"user": "user123"})
	createJWTHeader()
	createJWTPayload("user123")
	createJWTSignature("token")
	createJWTClaims("user123")
	createJWTIssuer()
	createJWTSubject("user123")
	createJWTAudience()
	createJWTExpiration()
	createJWTIssuedAt()
	createJWTNotBefore()
	createJWTID()
	createJWTType()
	createJWTAlgorithm()
	createJWTAlg()
	createJWTTyp()
	createJWTKid()
	createJWTX5u()
	createJWTX5c()
	createJWTX5t()
	createJWTX5tS256()
	createJWTCrit()
	createJWTCty()
	createJWTZip()
	createJWTHS256()
	createJWTHS384()
	createJWTHS512()
	createJWTRS256()
	createJWTRS384()
	createJWTRS512()
	createJWTES256()
	createJWTES384()
	createJWTES512()
	createJWTPS256()
	createJWTPS384()
	createJWTPS512()
	createJWTNone()
	createJWTNbf()
	createJWTExp()
	createJWTIat()
	createJWTIss()
	createJWTSub("user123")
	createJWTAud()
	createJWTJti()
	createJWTAzp()
	createJWTAuthTime()
	createJWTNonce()
	createJWTAcr()
	createJWTAmr()
	createJWTCnf()
	createJWTSid()
	createJWTSubJwk()
	createJWTEvents()
	createJWTToe()
	createJWTTxn()
	createJWTRur()
	createJWTPnu()
	createJWTAceProfile()
	createJWTCHash()
	createJWTAtHash()
	createJWTSHash()
}

// BAD: Insecure JWT arguments
func callWithJWTArgs() {
	// VULNERABILITY: Insecure JWT arguments
	createJWTToken("")
	generateJWTToken("")
	signJWTToken(nil)
	verifyJWTToken("")
	validateJWTToken("")
	decodeJWTToken("")
	encodeJWTToken(nil)
	createJWTHeader()
	createJWTPayload("")
	createJWTSignature("")
	createJWTClaims("")
	createJWTIssuer()
	createJWTSubject("")
	createJWTAudience()
	createJWTExpiration()
	createJWTIssuedAt()
	createJWTNotBefore()
	createJWTID()
	createJWTType()
	createJWTAlgorithm()
	createJWTAlg()
	createJWTTyp()
	createJWTKid()
	createJWTX5u()
	createJWTX5c()
	createJWTX5t()
	createJWTX5tS256()
	createJWTCrit()
	createJWTCty()
	createJWTZip()
	createJWTHS256()
	createJWTHS384()
	createJWTHS512()
	createJWTRS256()
	createJWTRS384()
	createJWTRS512()
	createJWTES256()
	createJWTES384()
	createJWTES512()
	createJWTPS256()
	createJWTPS384()
	createJWTPS512()
	createJWTNone()
	createJWTNbf()
	createJWTExp()
	createJWTIat()
	createJWTIss()
	createJWTSub("")
	createJWTAud()
	createJWTJti()
	createJWTAzp()
	createJWTAuthTime()
	createJWTNonce()
	createJWTAcr()
	createJWTAmr()
	createJWTCnf()
	createJWTSid()
	createJWTSubJwk()
	createJWTEvents()
	createJWTToe()
	createJWTTxn()
	createJWTRur()
	createJWTPnu()
	createJWTAceProfile()
	createJWTCHash()
	createJWTAtHash()
	createJWTSHash()
}

// GOOD: Secure JWT implementation
type SecureJWT struct {
	Token        string
	Header       map[string]interface{}
	Payload      map[string]interface{}
	Signature    string
	Claims       map[string]interface{}
	Issuer       string
	Subject      string
	Audience     string
	Expiration   int64
	IssuedAt     int64
	NotBefore    int64
	JWTID        string
	Type         string
	Algorithm    string
	Alg          string
	Typ          string
	Kid          string
	X5u          string
	X5c          string
	X5t          string
	X5tS256      string
	Crit         []string
	Cty          string
	Zip          string
	HS256        string
	HS384        string
	HS512        string
	RS256        string
	RS384        string
	RS512        string
	ES256        string
	ES384        string
	ES512        string
	PS256        string
	PS384        string
	PS512        string
	None         string
	Nbf          int64
	Exp          int64
	Iat          int64
	Iss          string
	Sub          string
	Aud          string
	Jti          string
	Azp          string
	AuthTime     int64
	Nonce        string
	Acr          string
	Amr          []string
	Cnf          map[string]interface{}
	Sid          string
	SubJwk       map[string]interface{}
	Events       map[string]interface{}
	Toe          int64
	Txn          string
	Rur          string
	Pnu          string
	AceProfile   string
	CHash        string
	AtHash       string
	SHash        string
}

// GOOD: Secure JWT creation
func createSecureJWT(userID string) *SecureJWT {
	// Safe: Secure JWT creation with proper validation
	if userID == "" {
		return nil
	}
	
	return &SecureJWT{
		Token:      "secure_jwt_token",
		Header:     map[string]interface{}{"alg": "RS256", "typ": "JWT"},
		Payload:    map[string]interface{}{"sub": userID, "iat": time.Now().Unix(), "exp": time.Now().Add(1 * time.Hour).Unix()},
		Signature:  "secure_signature",
		Claims:     map[string]interface{}{"sub": userID, "iat": time.Now().Unix(), "exp": time.Now().Add(1 * time.Hour).Unix()},
		Issuer:     "secure_issuer",
		Subject:    userID,
		Audience:   "secure_audience",
		Expiration: time.Now().Add(1 * time.Hour).Unix(),
		IssuedAt:   time.Now().Unix(),
		NotBefore:  time.Now().Unix(),
		JWTID:      "secure_jwt_id",
		Type:       "JWT",
		Algorithm:  "RS256",
		Alg:        "RS256",
		Typ:        "JWT",
		Kid:        "secure_key_id",
		X5u:        "secure_x5u",
		X5c:        "secure_x5c",
		X5t:        "secure_x5t",
		X5tS256:    "secure_x5t_s256",
		Crit:       []string{"secure_crit"},
		Cty:        "secure_cty",
		Zip:        "DEF",
		HS256:      "HS256",
		HS384:      "HS384",
		HS512:      "HS512",
		RS256:      "RS256",
		RS384:      "RS384",
		RS512:      "RS512",
		ES256:      "ES256",
		ES384:      "ES384",
		ES512:      "ES512",
		PS256:      "PS256",
		PS384:      "PS384",
		PS512:      "PS512",
		None:       "none",
		Nbf:        time.Now().Unix(),
		Exp:        time.Now().Add(1 * time.Hour).Unix(),
		Iat:        time.Now().Unix(),
		Iss:        "secure_issuer",
		Sub:        userID,
		Aud:        "secure_audience",
		Jti:        "secure_jwt_jti",
		Azp:        "secure_azp",
		AuthTime:   time.Now().Unix(),
		Nonce:      "secure_nonce",
		Acr:        "secure_acr",
		Amr:        []string{"pwd", "otp"},
		Cnf:        map[string]interface{}{"cnf": "secure_cnf"},
		Sid:        "secure_sid",
		SubJwk:     map[string]interface{}{"sub_jwk": "secure_sub_jwk"},
		Events:     map[string]interface{}{"events": "secure_events"},
		Toe:        time.Now().Unix(),
		Txn:        "secure_txn",
		Rur:        "secure_rur",
		Pnu:        "secure_pnu",
		AceProfile: "secure_ace_profile",
		CHash:      "secure_c_hash",
		AtHash:     "secure_at_hash",
		SHash:      "secure_s_hash",
	}
}

// GOOD: Secure JWT authentication
func secureAuthenticateJWT(token string) bool {
	// Safe: Secure JWT authentication with proper validation
	if token == "" {
		return false
	}
	
	// Validate token format and signature
	if !isValidJWTTokenFormat(token) {
		return false
	}
	
	// Check token expiration
	if isJWTTokenExpired(token) {
		return false
	}
	
	// Verify token signature
	if !verifyJWTTokenSignature(token) {
		return false
	}
	
	return true
}

// GOOD: Secure JWT authorization
func secureAuthorizeJWT(userID string, permission string) bool {
	// Safe: Secure JWT authorization with proper validation
	if userID == "" || permission == "" {
		return false
	}
	
	// Check user permissions
	if !hasJWTUserPermission(userID, permission) {
		return false
	}
	
	return true
}

// GOOD: Secure JWT token creation
func secureCreateJWTToken(userID string) string {
	// Safe: Secure JWT token creation with proper validation
	if userID == "" {
		return ""
	}
	
	// Use secure algorithm (RS256 instead of HS256)
	algorithm := "RS256"
	
	// Set secure expiration (1 hour instead of 24 hours)
	expiration := time.Now().Add(1 * time.Hour).Unix()
	
	// Create secure payload
	payload := map[string]interface{}{
		"sub": userID,
		"iat": time.Now().Unix(),
		"exp": expiration,
		"iss": "secure_issuer",
		"aud": "secure_audience",
	}
	
	// Sign with secure private key
	return signJWTWithSecureKey(payload, algorithm)
}

// GOOD: Secure JWT token validation
func secureValidateJWTToken(token string) bool {
	// Safe: Secure JWT token validation with proper checks
	if token == "" {
		return false
	}
	
	// Check for dangerous algorithms
	if containsDangerousJWTAlgorithms(token) {
		return false
	}
	
	// Validate token structure
	if !isValidJWTTokenStructure(token) {
		return false
	}
	
	// Check token expiration
	if isJWTTokenExpired(token) {
		return false
	}
	
	return true
}

// Helper functions for secure examples
func isValidJWTTokenFormat(token string) bool {
	// Implementation would validate JWT token format
	return len(token) > 0 && strings.Contains(token, ".")
}

func isJWTTokenExpired(token string) bool {
	// Implementation would check JWT token expiration
	return false
}

func verifyJWTTokenSignature(token string) bool {
	// Implementation would verify JWT token signature
	return true
}

func hasJWTUserPermission(userID string, permission string) bool {
	// Implementation would check JWT user permissions
	return true
}

func signJWTWithSecureKey(payload map[string]interface{}, algorithm string) string {
	// Implementation would sign JWT with secure private key
	return "secure_signed_jwt_token"
}

func containsDangerousJWTAlgorithms(token string) bool {
	// Implementation would check for dangerous JWT algorithms
	dangerousAlgorithms := []string{
		"none", "HS256", "HS384", "HS512", // Weak algorithms
	}
	
	tokenLower := strings.ToLower(token)
	for _, algorithm := range dangerousAlgorithms {
		if strings.Contains(tokenLower, strings.ToLower(algorithm)) {
			return true
		}
	}
	return false
}

func isValidJWTTokenStructure(token string) bool {
	// Implementation would validate JWT token structure
	return strings.Count(token, ".") == 2 // Header.Payload.Signature
}

// GOOD: Secure JWT handler
func secureJWTHandler(w http.ResponseWriter, r *http.Request) {
	// Safe: Secure JWT handling
	token := r.Header.Get("Authorization")
	
	// Remove "Bearer " prefix
	if strings.HasPrefix(token, "Bearer ") {
		token = strings.TrimPrefix(token, "Bearer ")
	}
	
	if !secureAuthenticateJWT(token) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	
	userID := r.Header.Get("X-User-ID")
	permission := "read"
	
	if !secureAuthorizeJWT(userID, permission) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	
	// Create secure JWT token
	secureToken := secureCreateJWTToken(userID)
	
	// Validate secure JWT token
	if !secureValidateJWTToken(secureToken) {
		http.Error(w, "Invalid token", http.StatusBadRequest)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "{\"status\": \"success\", \"token\": \"%s\"}", secureToken)
} 