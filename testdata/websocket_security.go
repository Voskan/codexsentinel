package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

// WebSocket Security Issues Examples

// Insecure WebSocket connection without authentication
func insecureWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true // INSECURE: Accepts all origins
		},
	}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No authentication check
	handleWebSocketConnection(conn)
}

// Insecure WebSocket with weak authentication
func weakAuthWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			return origin == "http://localhost:8080" // INSECURE: Weak origin check
		},
	}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// Weak authentication
	token := r.URL.Query().Get("token")
	if token == "admin" { // INSECURE: Hardcoded token
		handleWebSocketConnection(conn)
	}
}

// Insecure WebSocket without rate limiting
func noRateLimitWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No rate limiting - vulnerable to DoS
	for {
		messageType, message, err := conn.ReadMessage()
		if err != nil {
			break
		}
		
		// Process message without any limits
		processWebSocketMessage(conn, messageType, message)
	}
}

// Insecure WebSocket without input validation
func noValidationWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	for {
		messageType, message, err := conn.ReadMessage()
		if err != nil {
			break
		}
		
		// No input validation - vulnerable to injection
		conn.WriteMessage(messageType, message)
	}
}

// Insecure WebSocket without proper error handling
func insecureErrorWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		// INSECURE: Exposing internal errors
		http.Error(w, fmt.Sprintf("Upgrade failed: %v", err), http.StatusInternalServerError)
		return
	}
	defer conn.Close()
	
	handleWebSocketConnection(conn)
}

// Insecure WebSocket without compression protection
func insecureCompressionWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{
		EnableCompression: true, // INSECURE: Compression can lead to CRIME attack
	}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	handleWebSocketConnection(conn)
}

// Insecure WebSocket without proper close handling
func insecureCloseWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	// INSECURE: No proper close handling
	// defer conn.Close() - missing
	
	handleWebSocketConnection(conn)
}

// Insecure WebSocket without message size limits
func noMessageSizeLimitWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
	}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No message size limits - vulnerable to memory exhaustion
	for {
		messageType, message, err := conn.ReadMessage()
		if err != nil {
			break
		}
		
		// Process message without size limits
		processWebSocketMessage(conn, messageType, message)
	}
}

// Insecure WebSocket without proper ping/pong handling
func noPingPongWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No ping/pong handling - connections may hang
	for {
		messageType, message, err := conn.ReadMessage()
		if err != nil {
			break
		}
		
		processWebSocketMessage(conn, messageType, message)
	}
}

// Insecure WebSocket without proper subprotocol validation
func insecureSubprotocolWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{
		Subprotocols: []string{"chat", "game"}, // INSECURE: No validation
	}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No subprotocol validation
	handleWebSocketConnection(conn)
}

// Insecure WebSocket without proper headers validation
func insecureHeadersWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No headers validation
	userAgent := r.Header.Get("User-Agent")
	if userAgent != "" {
		// Process without validation
		handleWebSocketConnection(conn)
	}
}

// Insecure WebSocket without proper cookies validation
func insecureCookiesWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No cookies validation
	sessionCookie, err := r.Cookie("session")
	if err == nil {
		// Use session without validation
		handleWebSocketConnection(conn)
	}
}

// Insecure WebSocket without proper query parameters validation
func insecureQueryWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No query parameters validation
	userID := r.URL.Query().Get("user_id")
	if userID != "" {
		// Use user_id without validation
		handleWebSocketConnection(conn)
	}
}

// Insecure WebSocket without proper path validation
func insecurePathWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No path validation
	path := r.URL.Path
	if path == "/ws/chat" {
		// Allow access without proper validation
		handleWebSocketConnection(conn)
	}
}

// Insecure WebSocket without proper method validation
func insecureMethodWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No method validation
	if r.Method == "GET" {
		// Allow any GET request
		handleWebSocketConnection(conn)
	}
}

// Insecure WebSocket without proper timeout handling
func noTimeoutWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No timeout handling - connections may hang indefinitely
	for {
		messageType, message, err := conn.ReadMessage()
		if err != nil {
			break
		}
		
		processWebSocketMessage(conn, messageType, message)
	}
}

// Insecure WebSocket without proper heartbeat
func noHeartbeatWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No heartbeat mechanism
	handleWebSocketConnection(conn)
}

// Insecure WebSocket without proper reconnection handling
func noReconnectionWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No reconnection handling
	handleWebSocketConnection(conn)
}

// Insecure WebSocket without proper backoff handling
func noBackoffWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No backoff handling
	handleWebSocketConnection(conn)
}

// Insecure WebSocket without proper jitter handling
func noJitterWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No jitter handling
	handleWebSocketConnection(conn)
}

// Insecure WebSocket without proper random handling
func noRandomWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No random handling
	handleWebSocketConnection(conn)
}

// Insecure WebSocket without proper secure handling
func noSecureWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No secure handling
	handleWebSocketConnection(conn)
}

// Insecure WebSocket without proper TLS handling
func noTLSWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No TLS handling
	handleWebSocketConnection(conn)
}

// Insecure WebSocket without proper SSL handling
func noSSLWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No SSL handling
	handleWebSocketConnection(conn)
}

// Insecure WebSocket without proper certificate handling
func noCertificateWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No certificate handling
	handleWebSocketConnection(conn)
}

// Insecure WebSocket without proper key handling
func noKeyWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No key handling
	handleWebSocketConnection(conn)
}

// Insecure WebSocket without proper PEM handling
func noPEMWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No PEM handling
	handleWebSocketConnection(conn)
}

// Insecure WebSocket without proper CRT handling
func noCRTWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No CRT handling
	handleWebSocketConnection(conn)
}

// Insecure WebSocket without proper CA handling
func noCAWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No CA handling
	handleWebSocketConnection(conn)
}

// Insecure WebSocket without proper CA bundle handling
func noCABundleWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No CA bundle handling
	handleWebSocketConnection(conn)
}

// Insecure WebSocket without proper verify handling
func noVerifyWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No verify handling
	handleWebSocketConnection(conn)
}

// Insecure WebSocket without proper validation handling
func noValidationWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No validation handling
	handleWebSocketConnection(conn)
}

// Insecure WebSocket without proper sanitize handling
func noSanitizeWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No sanitize handling
	handleWebSocketConnection(conn)
}

// Insecure WebSocket without proper escape handling
func noEscapeWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No escape handling
	handleWebSocketConnection(conn)
}

// Insecure WebSocket without proper encode handling
func noEncodeWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No encode handling
	handleWebSocketConnection(conn)
}

// Insecure WebSocket without proper decode handling
func noDecodeWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No decode handling
	handleWebSocketConnection(conn)
}

// Insecure WebSocket without proper serialize handling
func noSerializeWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No serialize handling
	handleWebSocketConnection(conn)
}

// Insecure WebSocket without proper deserialize handling
func noDeserializeWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No deserialize handling
	handleWebSocketConnection(conn)
}

// Insecure WebSocket without proper marshal handling
func noMarshalWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No marshal handling
	handleWebSocketConnection(conn)
}

// Insecure WebSocket without proper unmarshal handling
func noUnmarshalWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No unmarshal handling
	handleWebSocketConnection(conn)
}

// Insecure WebSocket without proper JSON handling
func noJSONWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No JSON handling
	handleWebSocketConnection(conn)
}

// Insecure WebSocket without proper XML handling
func noXMLWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No XML handling
	handleWebSocketConnection(conn)
}

// Insecure WebSocket without proper protobuf handling
func noProtobufWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No protobuf handling
	handleWebSocketConnection(conn)
}

// Insecure WebSocket without proper msgpack handling
func noMsgpackWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No msgpack handling
	handleWebSocketConnection(conn)
}

// Insecure WebSocket without proper avro handling
func noAvroWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No avro handling
	handleWebSocketConnection(conn)
}

// Insecure WebSocket without proper thrift handling
func noThriftWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No thrift handling
	handleWebSocketConnection(conn)
}

// Insecure WebSocket without proper gRPC handling
func noGRPCWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No gRPC handling
	handleWebSocketConnection(conn)
}

// Insecure WebSocket without proper RPC handling
func noRPCWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No RPC handling
	handleWebSocketConnection(conn)
}

// Insecure WebSocket without proper remote handling
func noRemoteWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No remote handling
	handleWebSocketConnection(conn)
}

// Insecure WebSocket without proper call handling
func noCallWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No call handling
	handleWebSocketConnection(conn)
}

// Insecure WebSocket without proper invoke handling
func noInvokeWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No invoke handling
	handleWebSocketConnection(conn)
}

// Insecure WebSocket without proper execute handling
func noExecuteWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No execute handling
	handleWebSocketConnection(conn)
}

// Insecure WebSocket without proper process handling
func noProcessWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No process handling
	handleWebSocketConnection(conn)
}

// Insecure WebSocket without proper handle handling
func noHandleWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No handle handling
	handleWebSocketConnection(conn)
}

// Insecure WebSocket without proper route handling
func noRouteWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No route handling
	handleWebSocketConnection(conn)
}

// Insecure WebSocket without proper router handling
func noRouterWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No router handling
	handleWebSocketConnection(conn)
}

// Insecure WebSocket without proper dispatcher handling
func noDispatcherWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No dispatcher handling
	handleWebSocketConnection(conn)
}

// Insecure WebSocket without proper handler handling
func noHandlerWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No handler handling
	handleWebSocketConnection(conn)
}

// Insecure WebSocket without proper middleware handling
func noMiddlewareWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No middleware handling
	handleWebSocketConnection(conn)
}

// Insecure WebSocket without proper interceptor handling
func noInterceptorWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No interceptor handling
	handleWebSocketConnection(conn)
}

// Insecure WebSocket without proper filter handling
func noFilterWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No filter handling
	handleWebSocketConnection(conn)
}

// Insecure WebSocket without proper gateway handling
func noGatewayWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No gateway handling
	handleWebSocketConnection(conn)
}

// Insecure WebSocket without proper proxy handling
func noProxyWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No proxy handling
	handleWebSocketConnection(conn)
}

// Insecure WebSocket without proper load balancer handling
func noLoadBalancerWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No load balancer handling
	handleWebSocketConnection(conn)
}

// Insecure WebSocket without proper reverse proxy handling
func noReverseProxyWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No reverse proxy handling
	handleWebSocketConnection(conn)
}

// Insecure WebSocket without proper CDN handling
func noCDNWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No CDN handling
	handleWebSocketConnection(conn)
}

// Insecure WebSocket without proper cache handling
func noCacheWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No cache handling
	handleWebSocketConnection(conn)
}

// Insecure WebSocket without proper compression handling
func noCompressionWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No compression handling
	handleWebSocketConnection(conn)
}

// Insecure WebSocket without proper gzip handling
func noGzipWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No gzip handling
	handleWebSocketConnection(conn)
}

// Insecure WebSocket without proper deflate handling
func noDeflateWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No deflate handling
	handleWebSocketConnection(conn)
}

// Insecure WebSocket without proper brotli handling
func noBrotliWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No brotli handling
	handleWebSocketConnection(conn)
}

// Insecure WebSocket without proper lz4 handling
func noLZ4WebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No lz4 handling
	handleWebSocketConnection(conn)
}

// Insecure WebSocket without proper snappy handling
func noSnappyWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No snappy handling
	handleWebSocketConnection(conn)
}

// Insecure WebSocket without proper zstd handling
func noZstdWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No zstd handling
	handleWebSocketConnection(conn)
}

// Insecure WebSocket without proper lzma handling
func noLZMAWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// No lzma handling
	handleWebSocketConnection(conn)
}

// Helper functions
func handleWebSocketConnection(conn *websocket.Conn) {
	// Handle WebSocket connection
	for {
		messageType, message, err := conn.ReadMessage()
		if err != nil {
			break
		}
		
		// Echo message back
		conn.WriteMessage(messageType, message)
	}
}

func processWebSocketMessage(conn *websocket.Conn, messageType int, message []byte) {
	// Process WebSocket message
	conn.WriteMessage(messageType, message)
}

// Secure WebSocket examples (for comparison)
func secureWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			allowedOrigins := []string{"https://example.com", "https://app.example.com"}
			for _, allowed := range allowedOrigins {
				if origin == allowed {
					return true
				}
			}
			return false
		},
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		EnableCompression: false, // Disable compression for security
	}
	
	// Validate authentication
	token := r.URL.Query().Get("token")
	if !validateToken(token) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		http.Error(w, "Upgrade failed", http.StatusInternalServerError)
		return
	}
	defer conn.Close()
	
	// Set read deadline
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	
	// Handle connection with proper validation
	handleSecureWebSocketConnection(conn)
}

func validateToken(token string) bool {
	// Implement proper token validation
	return token != "" && len(token) > 10
}

func handleSecureWebSocketConnection(conn *websocket.Conn) {
	// Handle WebSocket connection with proper validation
	for {
		messageType, message, err := conn.ReadMessage()
		if err != nil {
			break
		}
		
		// Validate message size
		if len(message) > 1024 {
			conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseMessageTooBig, "Message too large"))
			break
		}
		
		// Validate and sanitize message
		sanitizedMessage := sanitizeMessage(message)
		if sanitizedMessage == nil {
			conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseUnsupportedData, "Invalid message"))
			break
		}
		
		// Process message
		conn.WriteMessage(messageType, sanitizedMessage)
	}
}

func sanitizeMessage(message []byte) []byte {
	// Implement proper message sanitization
	if len(message) == 0 {
		return nil
	}
	return message
} 