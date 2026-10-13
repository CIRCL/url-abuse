# Web interface

## Layout

Every page extends `templates/layouts/base.html`, which holds the `<head>`
(fonts, `app.css`, `theme.js`), the header (`partials/header.html`), the
`main` block and the footer (`partials/footer.html`).

| Block | Content |
|---|---|
| `title` | prefix of the `<title>`, ending with ` · ` (`API · CIRCL URL Abuse`) |
| `description` | `<meta name="description">` |
| `head` | page CSS |
| `main` | the page |
| `scripts` | page scripts (and `<template>`s), at the end of `<body>` |

A new page: a template in `templates/` that extends the layout, a route in
`website/web/__init__.py`, a test in `tests/unit/`.

`urlabuse_version` (package version) is available in every template.

| Page | Route | Template |
|---|---|---|
| Home: check a URL | `/` | `index.html` + `static/app.js` |
| API reference | `/api` | `api.html` + `static/api.js` (doc/api/v2.md) |
| Credits & licenses | `/credits` | `credits.html`, data in `website/web/credits_data.py` |
| Errors (404, 405, 500) | — | `error.html` (doc/api/v2.md) |

## Footer

On every page: what URL Abuse is and the privacy notice, then links (API,
Credits & licenses, Source code, About), the version, and the theme button.

## Credits & licenses

`/credits` lists what URL Abuse is built with, by section (Backend,
Interface, Sources), with the license and the role of each. The list is
`CREDITS` in `website/web/credits_data.py`: **add a line when a library,
font, service or provider is added**. The version shown is the installed
version of the Python `package`, or the pinned commit of a `vendor` library
(`static/vendor/<name>/COMMIT`, written by `tools/3rdparty.py`).

## Light and dark themes

Colours are CSS custom properties at the top of `static/app.css` (light by
default). The dark values apply:

- with `data-theme="dark"` on `<html>` (chosen by the visitor), or
- when the system is dark (`prefers-color-scheme: dark`), unless the visitor
  chose light (`data-theme="light"`).

The footer button (`#theme-toggle`) cycles **Auto → Light → Dark**.
`static/theme.js` is loaded in `<head>`, not deferred, so the saved choice
(`localStorage`, key `urlabuse-theme`) is applied before the first paint; Auto
removes the attribute. Any rule that depends on the theme is written twice,
like the tokens:

```css
:root[data-theme="dark"] .thing { … }
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) .thing { … }
}
```

Images that differ per theme use the `only-light` / `only-dark` classes (a
`<picture>` media query would not follow the button). The API reference
(vitrine) follows the theme because `app.css` maps our tokens onto its
`--vt-*` tokens.

## URL field animation

Example links are "typed" in the placeholder of the URL field (end of
`static/app.js`): only the placeholder changes, it stops on focus or input,
and is off with `prefers-reduced-motion`.
