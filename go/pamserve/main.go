package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
)

const socketPath = "/var/run/pam_unix.sock"

func main() {
	if err := os.RemoveAll(socketPath); err != nil {
		log.Fatalf("Failed to remove existing socket file: %v", err)
	}

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Fatalf("Failed to listen on Unix socket: %v", err)
	}
	defer listener.Close()
	os.Chmod(socketPath, 0o600) // slight race between getting the socket and setting perms...

	fmt.Printf("Server is listening on Unix socket: %s\n", socketPath)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-sigCh
		fmt.Println("\nShutting down server...")
		cancel()
		listener.Close()
		os.Remove(socketPath)
		os.Exit(0)
	}()

	// Accept incoming connections
	for {
		select {
		case <-ctx.Done():
			break
		default:
		}
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}
		go handle(conn)
	}
}

// handle reads data from the connection and processes it.
func handle(conn net.Conn) {
	// we do a single read for the data and than "handle" it
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		if err == io.EOF {
			log.Printf("Client close connection")
		}
		log.Printf("Error reading from connection: %v", err)
	}
	process(conn, buf[:n])
}

// process handles the received data.
func process(conn net.Conn, data []byte) {
	defer conn.Close()

	scanner := bufio.NewScanner(bytes.NewReader(data))
	i := 0
	pam := PamUnixSock{}
	for scanner.Scan() {
		switch i {
		case 0:
			pam.username = scanner.Text()
		case 1:
			pam.service = scanner.Text()
		case 2:
			pam.prompt = scanner.Text()
		}
		i++
	}

	log.Printf("Seen: %s\n", pam)

	ok := []byte("1\n")

	_, err := conn.Write(ok)
	if err != nil {
		log.Printf("Failed to write to connection: %v", err)
	}
}

type PamUnixSock struct {
	username string
	service  string
	prompt   string
}

func (p PamUnixSock) String() string {
	return fmt.Sprintf("user %q - service %s - prompt %q", p.username, p.service, p.prompt)
}
