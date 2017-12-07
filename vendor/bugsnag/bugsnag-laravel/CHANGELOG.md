Changelog
=========

## 2.6.0 (2017-06-29)

### Enhancements

* Support capturing user information from generic user objects
  [Simon Bennett](https://github.com/mrsimonbennett)
  [#207](https://github.com/bugsnag/bugsnag-laravel/pull/207)

* Support setting release stage within configuration file
  [Graham Campbell](https://github.com/GrahamCampbell)
  [#228](https://github.com/bugsnag/bugsnag-laravel/pull/228)

## 2.5.0 (2017-04-06)

### Enhancements

* Include more deeply nested exception causes in reports

### Bug Fixes

* Improve phar support by falling back to relative paths when needed
  [Graham Campbell](https://github.com/GrahamCampbell)
  [#223](https://github.com/bugsnag/bugsnag-laravel/pull/223)

## 2.4.0 (2016-09-08)

### Enhancements

* Added more configuration options
  [Graham Campbell](https://github.com/GrahamCampbell)
  [#199](https://github.com/bugsnag/bugsnag-laravel/pull/199)

### Bug Fixes

* Fixed the app type getting overwritten
  [Graham Campbell](https://github.com/GrahamCampbell)
  [#196](https://github.com/bugsnag/bugsnag-laravel/pull/196)

## 2.3.0 (2016-08-19)

### Enhancements

* Record the queue context and job information
  [Graham Campbell](https://github.com/GrahamCampbell)
  [#183](https://github.com/bugsnag/bugsnag-laravel/pull/183)

* Replaced event logging with query recording
  [Graham Campbell](https://github.com/GrahamCampbell)
  [#186](https://github.com/bugsnag/bugsnag-laravel/pull/186)

### Bug Fixes

* Fixed the deploy command option descriptions
  [Andrew Brown](https://github.com/browner12)
  [#178](https://github.com/bugsnag/bugsnag-laravel/pull/178)

## 2.2.0 (2016-08-08)

### Enhancements

* Added a `bugsnag:deploy` console command
  [Graham Campbell](https://github.com/GrahamCampbell)
  [#154](https://github.com/bugsnag/bugsnag-laravel/pull/154)

* Record events as breadrumbs
  [Graham Campbell](https://github.com/GrahamCampbell)
  [#159](https://github.com/bugsnag/bugsnag-laravel/pull/159)

* Support both guzzle 5 and 6
  [Graham Campbell](https://github.com/GrahamCampbell)
  [#164](https://github.com/bugsnag/bugsnag-laravel/pull/164)

* Set the app type automatically
  [Graham Campbell](https://github.com/GrahamCampbell)
  [#167](https://github.com/bugsnag/bugsnag-laravel/pull/167)

* Fixed certificate verification on some systems
  [Graham Campbell](https://github.com/GrahamCampbell)
  [#176](https://github.com/bugsnag/bugsnag-laravel/pull/176)

### Bug Fixes

* Fixed support for older laravel versions
  [Graham Campbell](https://github.com/GrahamCampbell)
  [#173](https://github.com/bugsnag/bugsnag-laravel/pull/173)

## 2.1.0 (2016-07-25)

### Enhancements

* Implement Laravel's logger contract
  [Graham Campbell](https://github.com/GrahamCampbell)
  [#147](https://github.com/bugsnag/bugsnag-laravel/pull/147)

### Bug Fixes

* Fixed container aliasing of the logger
  [Rémi Pelhate](https://github.com/remipelhate)
  [#151](https://github.com/bugsnag/bugsnag-laravel/pull/151)

## 2.0.2 (2016-07-18)

### Bug Fixes

* Removed support for using `HTTP_PROXY` environment variable for non-CLI apps
  per [CVE-2016-5385 (httpoxy)](https://httpoxy.org/).
  [Graham Campbell](https://github.com/GrahamCampbell)
  [#143](https://github.com/bugsnag/bugsnag-laravel/pull/143)
  [#145](https://github.com/bugsnag/bugsnag-laravel/pull/145)

* Convert `BUGSNAG_NOTIFY_RELEASE_STAGES` to a comma-delimited array
  [Jason](https://github.com/fire015)
  [Graham Campbell](https://github.com/GrahamCampbell)
  [#142](https://github.com/bugsnag/bugsnag-laravel/pull/142)
  [#144](https://github.com/bugsnag/bugsnag-laravel/pull/144)

## 2.0.1 (2016-07-08)

### Bug Fixes

* Lowered the minimum PHP version to 5.5.0
  [Graham Campbell](https://github.com/GrahamCampbell)
  [#138](https://github.com/bugsnag/bugsnag-laravel/pull/138)

## 2.0.0 (2016-07-07)

Our library has gone through some major improvements. The primary change to watch out for is we're no longer overriding your exception handler.

### Enhancements

* Since we're no longer overriding your exception handler, you'll need to restore your original handler, and then see our docs for how to bind our new logger to the container.

* If you'd like access to all our new configuration, you'll need to re-publish our config file.

### Bug Fixes

* Every bug

## 1.7.0 (2016-06-24)

### Enhancements

* Let Laravel decide whether to report or not
  [Phil Bates](https://github.com/philbates35)
  [#97](https://github.com/bugsnag/bugsnag-laravel/pull/97)

### Bug Fixes

* Fixed version constraint
  [Graham Campbell](https://github.com/GrahamCampbell)
  [#111](https://github.com/bugsnag/bugsnag-laravel/pull/111)

* Ensure the api key is a string
  [Graham Campbell](https://github.com/GrahamCampbell)
  [57afd32](https://github.com/bugsnag/bugsnag-laravel/commit/57afd321273486d4f24a96d9eb3f0938278c9f4d)

## 1.6.4 (2016-03-09)

### Bug Fixes

* Add missing 'config' tag in service provider
  [Dan Smith](https://github.com/DanSmith83)
  [#73](https://github.com/bugsnag/bugsnag-laravel/pull/73)

## 1.6.3 (2016-01-08)

### Bug Fixes

* Avoid initializing Bugsnag when no API key is set
  [Dries Vints](https://github.com/driesvints)
  [#72](https://github.com/bugsnag/bugsnag-laravel/pull/72)

## 1.6.2 (2015-12-08)

### Bug Fixes

* Added missing environment variables for configuration
  [Andrew Brown](https://github.com/browner12)
  [#71](https://github.com/bugsnag/bugsnag-laravel/pull/71)

## 1.6.1 (2015-07-22)

### Bug Fixes

* Fixed array syntax for older php
  [Timucin Gelici](https://github.com/timucingelici)
  [#63](https://github.com/bugsnag/bugsnag-laravel/pull/63)

## 1.6.0 (2015-07-14)

### Enhancements

* Added support for setting the api key using .env in Laravel 5+
  [Simon Maynard](https://github.com/snmaynard)
  [#62](https://github.com/bugsnag/bugsnag-laravel/pull/62)

* Added support for artisan vendor:publish
  [Simon Maynard](https://github.com/snmaynard)
  [#62](https://github.com/bugsnag/bugsnag-laravel/pull/62)

## 1.5.1 (2015-07-01)

### Bug Fixes

* Added a missing import in the Lumen service provider
  [Jake Toolson](https://github.com/jaketoolson)
  [#57](https://github.com/bugsnag/bugsnag-laravel/pull/57)

## 1.5.0 (2015-05-25)

### Enhancements

* Added Lumen support
  [Luca Critelli](https://github.com/lucacri)
  [#51](https://github.com/bugsnag/bugsnag-laravel/pull/51)

### Bug Fixes

* Fix bug with reading settings from service file
  [Eduardo Kasper](https://github.com/ehkasper)
  [#48](https://github.com/bugsnag/bugsnag-laravel/pull/48)

1.4.2
-----
-   Try/catch for missing/nonstandard auth service

1.4.1
-----
-   Default severity to 'error'

1.4.0
-----
-   Better laravel 5 support!

1.3.0
-----
-   Laravel 5 support!

1.2.1
-----
-   Protect against missing configuration variables (thanks @jasonlfunk!)

1.2.0
-----
-   Update `bugsnag-php` dependency to enable support for code snippets on
    your Bugsnag dashboard
-   Allow configuring of more Bugsnag settings from your `config.php`
    (thanks @jacobmarshall!)

1.1.1
-----
-   Fix issue where sending auth information with complex users could fail (thanks @hannesvdvreken!)

1.1.0
-----
-   Send user/auth information if available (thanks @hannesvdvreken!)

1.0.10
------
-   Laravel 5 support

1.0.9
------
-   Split strip paths from `inProject`

1.0.8
-----
-   Bump the bugsnag-php dependency to include recent fixes

1.0.7
-----
-   Fix major notification bug introduced in 1.0.6

1.0.6
-----
-   Fix incompatibility with PHP 5.3

1.0.5
-----
-   Identify as Laravel notifier instead of PHP

1.0.4
-----
-   Allow configuration of notify_release_stages from config file

1.0.3
-----
-   Fix bug when setting releaseStage in the ServiceProvider

1.0.2
-----
-   Fix laravel requirement to work with 4.1
-   Add a `Bugsnag` facade for quick access to $app["bugsnag"]

1.0.1
-----
-   Fixed fatal error handling
-   Set release stage based on laravel's `App::environment` setting

1.0.0
-----
-   Initial release
