package gokcp

import (
	"io"
	"log"
	"testing"
	"time"
)

func handleEcho(conn *Conn) {
	buf := make([]byte, 4096)
	for {
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			if err.Error() == "timeout" {
				conn.Close()
			}
			log.Println(err)
			return
		}
		log.Println("client", conn.RemoteAddr())
		n, err = conn.Write(buf[:n])
		if err != nil {
			log.Println(err)
			return
		}
	}
}

func Test_Server(t *testing.T) {
	listener, err := Listen("127.0.0.1:12345")
	if err == nil {
		// spin-up the client
		//go client()
		for {
			s, err := listener.AcceptKCP()
			if err != nil {
				log.Fatal(err)
			}
			go handleEcho(s)
		}
	} else {
		log.Fatal(err)
	}
}

func Test_Client(t *testing.T) {
	var sess1 *Conn
start:
	log.Println("reconnect")
	sess1, _ = Dial("127.0.0.1:12345")
	for {
		data := time.Now().String() + "+++"
		buf := make([]byte, len(data))
		log.Println("sent:", data)
		sess1.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := sess1.Write([]byte(data)); err == nil {
			// read back the data
			if _, err := io.ReadFull(sess1, buf); err == nil {
				log.Println("recv:", string(buf))
			} else {
				sess1.Close()
				log.Println(err)
				time.Sleep(time.Second)
				goto start
				//log.Println(err)
			}
		} else {
			sess1.Close()
			log.Println(err)
			time.Sleep(time.Second)
			goto start
			//log.Fatal(err)
		}
		time.Sleep(10 * time.Second)
	}
}
