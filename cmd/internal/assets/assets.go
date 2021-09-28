package assets

import (
	"embed"
)

//go:embed data/*
var fileSystem embed.FS

func Must(filename string) string {
	bytes, err := fileSystem.ReadFile(filename)
	if err != nil {
		panic(err)
	}
	return string(bytes)
}
