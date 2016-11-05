status-symlinks
===============

An [`nginx`](https://nginx.org/en/) module that serves various [kinds of HTTP
responses](https://en.wikipedia.org/wiki/List_of_HTTP_status_codes) based on
symlinks that it finds under the document root. This lets you easily make
redirects without having to edit `nginx`'s configuration, as well as serve
responses that aren't otherwise supported at all (like 410 Gone).

Copyright and License
---------------------

`status-symlinks` is copyright (C) 2016  Blacklight Shining
\<blacklightshining@derpymail.org> (PGP key C7106095)

`status-symlinks` is free software: you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the Free
Software Foundation, either version 3 of the License, or (at your option) any
later version.

`status-symlinks` is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

A copy of version 3 of the GNU General Public License is included with the
source of `status-symlinks`, as the `LICENSE` file. You can also find it online
at <https://www.gnu.org/licenses/>.

Build and Installation
----------------------

The `nginx` community wiki has [a page on compiling modules]
(https://www.nginx.com/resources/wiki/extending/compiling/).

This is currently a _static_ module (mostly because I only recently learned that
dynamic `nginx` modules are even a thing). The deal is, you extract this
module's source somewhere and pass `--add-module=$path_to/status-symlinks` to
`nginx`'s `./configure` script. You'll also need to get `make` to compile it

- As C99 (because C89 is _ancient_ at this point, and I need those
  [narrowly-scoped declarations and field-name initializers]
  (https://stackoverflow.com/q/2047065/what-are-the-most-useful-new-features-in-c99),
  dammit!)
- With `-ftrapv` (because I don't want to have to insert manual overflow checks
  before every bit of arithmetic, okay?)

You can accomplish this either by also passing
`--with-cc-opt="-std=gnu99 -ftrapv"` to `./configure` (which will cause _all of
`nginx`_ to be built with those options), or by hacking the makefiles after
`./configure` generates them (which is a bit more involved, though only a
bit…hint hint: `objs/Makefile`; search for the module's name) and adding the
options only to the `$(CC)` invocation that compiles this module.

Once that's done, just `make` and `make install` as normal. Because it's a
static module, there is no extra configuration needed to load it (though see
below for the extra configuration needed to _enable_ it).

Configuration
-------------

`status-symlinks` currently adds one [directive]
(https://nginx.org/en/docs/dirindex.html), aptly named `status_symlinks` (note
the underscore). This must be used if you want it to actually handle requests:
simply add `status_symlinks on;` to the relevant `location` blocks. You can also
use it at the `server` or even `http` level, if you wish.

Usage
-----

Usage is intended to be quick and simple, and—in my opinion :) —it is. For these
examples, we'll assume that your document root is `/var/www`. (The use of
`-i`—and `-T`, which is a GNU extension—are personal choices. I like to use them
in interactive invocations of `ln`, `mv`, etc to be sure I don't accidentally
clobber or misplace anything. You don't have to.)

```sh
# Redirect /foo on our site to a page on another site. Useful for shortening
# URIs, if nothing else. :)
ln -si 302:https://www.other-site.example/foobar -T /var/www/foo

# You can also use relative URIs.
ln -si 301:/foozogz -T /var/www/foo2

# Make it explicit that /deleted-foo used to exist, but doesn't anymore and
# won't be coming back.
ln -si 410: -T /var/www/deleted-foo

# These aren't status symlinks, and won't be handled by this module. nginx will
# either try to open the files they point to (which may or may not exist), or
# return 403 Forbidden. See the docs on the `disable_symlinks` directive:
# https://nginx.org/en/docs/http/ngx_http_core_module.html#disable_symlinks
ln -si 409: -T /var/www/bar
ln -si 503: -T /var/www/baz
ln -si 0301:https://www.some-other-site.example/ -T /var/www/qux
ln -si 042:/everything -T /var/www/quux
ln -si 64: -T /var/www/grault
ln -si garble -T /var/www/garply
```

Plans?
------

- The examples are nice, but this document also needs (and will get!) more
  formal documentation of how status symlinks are processed.
- I'm not sure about the behavior regarding status symlinks that are
  syntactically valid, and merely have a not- (or not-yet-) supported response
  code (e.g. the 409: and 503: ones, above). Might change it to return a 500 (or
  other suitable error), instead of passing the request on to other handlers.
- I'm planning to add support for sending a response with a body for most
  response codes. This will probably work by making those codes take a URI
  argument referring to a file to use as the body—for example,
  `ln -si 403:/you-shant-get-ye-flask%21.html -T /var/www/flask`.
