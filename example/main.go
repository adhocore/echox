package main

import (
	"os"
	"time"

	"github.com/adhocore/echox"
)

func main() {
	app := echox.New()

	isDev := os.Getenv("APP_ENV") == "dev"
	render := echox.Renderer("./example/tmpl/", ".html", isDev, nil)

	render.AddFunc("date", func(t time.Time, f string) string {
		return t.Format(f)
	})

	app.Renderer = render.Load()

	app.Get("/", func(c *echox.Context) error {
		// return c.Status(200).SendString("helloworld")
		return c.Renderx("index", echox.Map{
			"Now":    time.Now(),
			"Header": "This is header",
			"Footer": "This is footer",
		}, "layout")
	})

	app.Start(":2000")
}
