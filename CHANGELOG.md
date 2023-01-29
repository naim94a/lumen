# Changelog

## [Unreleased] - _TBD_
### Added
- This changelog.
- Support for IDA 8.1+ delete command.
- Pooling for connections to database.
- Attempt to cancel immutable database queries if client leaves.

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


[Unreleased]: https://github.com/naim94a/lumen/compare/8b78d0a7d5b3ef4e0f221b07903fa5252174b57b...HEAD
[v0.2.0]: https://github.com/naim94a/lumen/compare/v0.1.0...8b78d0a7d5b3ef4e0f221b07903fa5252174b57b
[v0.1.0]: https://github.com/naim94a/lumen/releases/tag/v0.1.0
