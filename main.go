package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	mqtt "github.com/mochi-mqtt/server/v2"
	"github.com/mochi-mqtt/server/v2/listeners"
	"github.com/mochi-mqtt/server/v2/packets"
)

type UsernamePasswordAuthHook struct {
	mqtt.HookBase
	ValidUsers map[string]string // username -> password
}

func NewUsernamePasswordAuthHook(users map[string]string) *UsernamePasswordAuthHook {
	return &UsernamePasswordAuthHook{
		ValidUsers: users,
	}
}

func (h *UsernamePasswordAuthHook) Provides(b byte) bool {
	return bytes.Contains([]byte{
		mqtt.OnConnectAuthenticate,
	}, []byte{b})
}

// OnConnectAuthenticate 实现 v2 版本的认证方法
func (h *UsernamePasswordAuthHook) OnConnectAuthenticate(cl *mqtt.Client, pk packets.Packet) bool {
	if !pk.Connect.UsernameFlag || !pk.Connect.PasswordFlag {
		fmt.Println("客户端未提供用户名或密码")
		return false
	}

	username := string(pk.Connect.Username)
	password := string(pk.Connect.Password)
	fmt.Println(username)
	fmt.Println(password)
	expectedPass, exists := h.ValidUsers[username]
	if !exists {
		fmt.Printf("用户不存在: %s\n", username)
		return false
	}

	if expectedPass != password {
		fmt.Printf("密码错误: %s\n", username)
		return false
	}

	fmt.Printf("登录成功: 用户名=%s\n", username)
	return true
}

func main() {
	sigs := make(chan os.Signal, 1)
	done := make(chan bool, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		done <- true
	}()

	tlsConfig := createTLSConfig()

	server := mqtt.New(nil)
	validUsers := map[string]string{
		"user1": "pass1",
		"admin": "password123",
	}
	_ = server.AddHook(NewUsernamePasswordAuthHook(validUsers), nil)
	_ = server.AddHook(new(messageLogger), &ExampleHookOptions{
		Server: server,
	})
	tcp := listeners.NewTCP(listeners.Config{
		ID:        "t1",
		Address:   ":1883",
		TLSConfig: tlsConfig,
	})
	err := server.AddListener(tcp)
	if err != nil {
		log.Fatal(err)
	}

	ws := listeners.NewWebsocket(listeners.Config{
		ID:        "ws1",
		Address:   ":1882",
		TLSConfig: tlsConfig,
	})
	err = server.AddListener(ws)
	if err != nil {
		log.Fatal(err)
	}

	stats := listeners.NewHTTPStats(
		listeners.Config{
			ID:        "stats",
			Address:   ":8080",
			TLSConfig: tlsConfig,
		}, server.Info,
	)
	err = server.AddListener(stats)
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		err := server.Serve()
		if err != nil {
			log.Fatal(err)
		}
	}()

	<-done
	server.Log.Warn("caught signal, stopping...")
	_ = server.Close()
	server.Log.Info("main.go finished")
}

func createTLSConfig() *tls.Config {
	// 加载服务端自己的证书和私钥
	cert, err := tls.LoadX509KeyPair("./cert/server.crt", "./cert/server.key")
	if err != nil {
		log.Fatalf("server: loadkeys: %s", err)
	}

	// 加载客户端 CA 证书
	clientCA, err := os.ReadFile("./cert/ca.crt")
	if err != nil {
		log.Fatalf("server: read client ca: %s", err)
	}

	// 创建一个证书池，并将客户端 CA 添加进去
	clientCAPool := x509.NewCertPool()
	ok := clientCAPool.AppendCertsFromPEM(clientCA)
	if !ok {
		log.Fatalf("failed to parse client CA certificate")
	}

	// 构建 TLS 配置
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert, // 强制要求客户端提供证书并验证
		ClientCAs:    clientCAPool,                   // 信任的客户端 CA
		MinVersion:   tls.VersionTLS12,
	}
	return tlsConfig
}

type ExampleHookOptions struct {
	Server *mqtt.Server
}

type messageLogger struct {
	mqtt.HookBase
}

// 实现 Serve 方法，这里我们只关心 OnMsgReceived 事件
func (h *messageLogger) ID() string {
	return "message-logger"
}

func (h *messageLogger) Provides(b byte) bool {
	return bytes.Contains([]byte{
		mqtt.OnPublish,
	}, []byte{b})
}

func (h *messageLogger) OnPublish(cl *mqtt.Client, pk packets.Packet) (packets.Packet, error) {
	fmt.Println("received from client", "client", cl.ID, "payload", string(pk.Payload))
	pkx := pk
	fmt.Println("received modified packet from client", "client", cl.ID, "payload", string(pkx.Payload))

	return pkx, nil
}
