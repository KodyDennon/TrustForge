# TrustForge .NET Adapters (Phase I)

Solution file: `Trustforge.AdapterSuite.sln`. Six packages plus their xUnit
test projects. All adapters delegate authorization to the local `tf-daemon`
via `POST /v1/decide` and never make decisions themselves.

| Package | Framework |
| --- | --- |
| `Trustforge.Sdk` | shared HTTP client, .NET 8 |
| `Trustforge.AspNetCore` | ASP.NET Core middleware + action filter |
| `Trustforge.OWIN` | OWIN middleware |
| `Trustforge.MinimalApi` | Minimal API endpoint extensions |
| `Trustforge.SignalR` | SignalR `IHubFilter` |
| `Trustforge.Orleans` | Orleans grain interceptor |

## Build

Requires the **.NET 8 SDK**.

```bash
dotnet test tools/adapters/dotnet/Trustforge.AdapterSuite.sln
```

If `dotnet` is not installed:

- macOS: `brew install --cask dotnet-sdk`
- Linux: https://learn.microsoft.com/dotnet/core/install/linux
- Windows: https://dotnet.microsoft.com/download

## Status

Draft (Phase I). Not production-ready.
