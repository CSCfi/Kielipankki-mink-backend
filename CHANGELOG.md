# Changelog

All notable API changes will be documented in this file. The format is based on [Keep a
Changelog](https://keepachangelog.com/en/1.0.0/).

## [unreleased]

### Added

- The `run.py` script is now a command line tool and the host, the port and logging can be configured with flags.
- `/upload-sources` now contains the exception message in the response in case invalid XML is uploaded.

## [1.1.0] - 2024-01-05

### Added

- Added new resource type: metadata YAML files. There are now calls for creating, uploading and downloading these.
- It is now possible to upload source files with uppercase file extensions.

### Changed

- The corpus registry and the job queue have been combined. Now, upon resource creation a job item is created immediately
  (instead of it being created first upon starting a Sparv job).
- The `/check-status`-call has been replaced with `/resource-info` with a different response format.

## [1.0.0] - 2023-09-19

This is the first release of the Mink backend! This application contains functionality for uploading and downloading
corpus-related files, processing corpora with [Sparv](https://spraakbanken.gu.se/sparv/) and installing them in
[Korp](https://spraakbanken.gu.se/korp) and [Strix](https://spraakbanken.gu.se/strix).

[unreleased]: https://github.com/spraakbanken/mink-backend/compare/v1.1.0...dev
[1.1.0]: https://github.com/spraakbanken/mink-backend/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/spraakbanken/mink-backend/releases/tag/v1.0.0
