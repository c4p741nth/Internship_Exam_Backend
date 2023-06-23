package main

import (
	"fmt"
	"log"

	"github.com/c4p741nth/Exam_Backend/initializers"
	"github.com/c4p741nth/Exam_Backend/models"
)

func init() {
	config, err := initializers.LoadConfig(".")
	if err != nil {
		log.Fatal("? Could not load environment variables", err)
	}

	initializers.ConnectDB(&config)
}

func main() {
	initializers.DB.AutoMigrate(&models.User{})
	initializers.DB.AutoMigrate(&models.Token{})
	fmt.Println("? Migration complete")
}
