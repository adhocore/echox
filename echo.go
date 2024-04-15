package echox

import (
	"time"

	"github.com/labstack/echo/v4"
)

type HandlerFunc = func(c *Context) error

type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return e.Message }

type Echo struct {
	*echo.Echo
}

func New() *Echo {
	e := echo.New()
	e.Binder = DefaultBinder

	e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			c.Set(ReqStart, time.Now())
			return next(&Context{c})
		}
	})
	return &Echo{Echo: e}
}

func (e *Echo) Uses(m func(c *Context, next echo.HandlerFunc) error) {
	e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			return m(c.(*Context), next)
		}
	})
}

func (e *Echo) Delete(path string, h HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	return e.Add("DELETE", path, Adapt(h), m...)
}

func (e *Echo) Get(path string, h HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	return e.Add("GET", path, Adapt(h), m...)
}

func (e *Echo) Patch(path string, h HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	return e.Add("PATCH", path, Adapt(h), m...)
}

func (e *Echo) Post(path string, h HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	return e.Add("POST", path, Adapt(h), m...)
}

func (e *Echo) Put(path string, h HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	return e.Add("PUT", path, Adapt(h), m...)
}

func (e *Echo) GetPost(path string, h HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	return e.Match([]string{"GET", "POST"}, path, Adapt(h), m...)[0]
}

func (e *Echo) Group(prefix string, m ...echo.MiddlewareFunc) (g *Group) {
	g = &Group{e.Echo.Group(prefix, m...)}
	g.Group.Use(m...)
	return
}
