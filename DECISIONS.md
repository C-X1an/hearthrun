# Engineering decisions

The following decisions define the intended runtime. They are not claims that native implementation is complete. Each ADR includes a removal/alternative rationale.

| ADR | Decision |
|---|---|
| [0001-native-scope](docs/adr/0001-native-scope.md) | Native Linux boundary with approved static fixtures |
| [0002-process-boundary](docs/adr/0002-process-boundary.md) | Separately exec a single-threaded launcher |
| [0003-completion](docs/adr/0003-completion.md) | Completion requires verified cleanup |
| [0004-artifact-descriptor](docs/adr/0004-artifact-descriptor.md) | Retain output FD and export after quiescence |
| [0005-local-control](docs/adr/0005-local-control.md) | Single owning supervisor and no database service |
| [0006-public-private](docs/adr/0006-public-private.md) | Publish a clean, reproducible product export |
