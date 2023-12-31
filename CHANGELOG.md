# Changelog

## [Unreleased] - _TBD_
### Added
- Implemented the function histories command.

## [v0.3.0] - 2023-08-22
### Added
- This changelog.
- Support for IDA 8.1+ delete command.
- Pooling for connections to database.
- Attempt to cancel immutable database queries if client leaves.
- Database migrations via Diesel ORM.
- Support for IDA 8.3+ hello response.
- Add Metrics for prometheus.

### Fixed
- 8K stack size is too small for debug builds.

## [v0.2.0] - 2022-10-12
### Added
- Protocol: support for IDA 8.1+ user authentication.
- Client connection duration limitations.
### Changed
- Tokio's thread size is reduced from 4M to 8K.

## [v0.1.0]  - 2021-01-21
This is Lumen's first tagged release. It contains a few fixes and dependency updates since the initial commit (2020-12-17).


[Unreleased]: https://github.com/naim94a/lumen/compare/v0.3.0...HEAD
[v0.3.0]: https://github.com/naim94a/lumen/compare/v0.2.0...v0.3.0
[v0.2.0]: https://github.com/naim94a/lumen/compare/v0.1.0...v0.2.0
[v0.1.0]: https://github.com/naim94a/lumen/releases/tag/v0.1.0
