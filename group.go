package echox

import "github.com/labstack/echo/v4"

type Group struct{ *echo.Group }

func (e *Group) Uses(m func(c *Context, next echo.HandlerFunc) error) {
	e.Group.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			return m(c.(*Context), next)
		}
	})
}

func (e *Group) Delete(path string, h HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	return e.Add("DELETE", path, Adapt(h), m...)
}

func (e *Group) Get(path string, h HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	return e.Add("GET", path, Adapt(h), m...)
}

func (e *Group) Patch(path string, h HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	return e.Add("PATCH", path, Adapt(h), m...)
}

func (e *Group) Post(path string, h HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	return e.Add("POST", path, Adapt(h), m...)
}

func (e *Group) Put(path string, h HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	return e.Add("PUT", path, Adapt(h), m...)
}

func (e *Group) GetPost(path string, h HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	return e.Group.Match([]string{"GET", "POST"}, path, Adapt(h), m...)[0]
}
