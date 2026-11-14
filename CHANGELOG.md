# Changelog

All notable changes to this project are documented in this file. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- `cookie-flags` check: reports cookies set by the home page and `/wp-login.php` that lack
  `Secure` (on HTTPS sites), and session cookies (WordPress login, `PHPSESSID`, WooCommerce)
  that lack `HttpOnly` or `SameSite`; `SameSite=None` without `Secure` is always reported.
  Cookie values are never stored or printed. Options: `paths`, `report_all`,
  `session_patterns`, `ignore`.
- `server-banner` check: reports software versions in `Server`, `X-Powered-By` and similar
  headers (low) and a PHP version below `min_php` (default `8.2`, medium). Options:
  `headers`, `min_php`.
- `plugin-versions` check: lists the plugins and themes referenced by the home page,
  reports plugins whose `readme.txt` is publicly readable (low) and, with the new
  `min_versions` option, plugins or themes older than a configured minimum (medium).
  Options: `probe_readme`, `max_probes`, `ignore`, `min_versions`.

### Changed

- Python 3.10 or newer is now required (`requires-python = ">=3.10"`), matching the CI matrix.
