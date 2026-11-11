# Changelog

All notable changes to this project are documented in this file. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- `plugin-versions` check: lists the plugins and themes referenced by the home page,
  reports plugins whose `readme.txt` is publicly readable (low) and, with the new
  `min_versions` option, plugins or themes older than a configured minimum (medium).
  Options: `probe_readme`, `max_probes`, `ignore`, `min_versions`.
