package main

import "gin-jwt/handlers"

func main() {
	r := handlers.New()
	// 监听并在 0.0.0.0:8080 上启动服务
	r.Run(":8080")
}
