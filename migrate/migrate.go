package main

import (
	"fmt"
	"go-rest-api/db"
	"go-rest-api/model"
	"log"
)

func main() {
	dbConn := db.NewDB()
	defer fmt.Println("マイグレーションに成功しました！")
	defer db.CloseDB(dbConn)
	err := dbConn.AutoMigrate(&model.User{}, &model.Task{})
	if err != nil {
		log.Fatalln("マイグレ失敗です...")
	}
}
