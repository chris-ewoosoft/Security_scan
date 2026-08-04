FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS base
WORKDIR /app

FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
ARG BUILD_CONFIGURATION=Release
WORKDIR /src

COPY ["src/workers/SecurityPortal.Worker.SSL/SecurityPortal.Worker.SSL.csproj", "src/workers/SecurityPortal.Worker.SSL/"]
COPY ["src/shared/SecurityPortal.Application/SecurityPortal.Application.csproj", "src/shared/SecurityPortal.Application/"]
COPY ["src/shared/SecurityPortal.Domain/SecurityPortal.Domain.csproj", "src/shared/SecurityPortal.Domain/"]
COPY ["src/shared/SecurityPortal.Infrastructure/SecurityPortal.Infrastructure.csproj", "src/shared/SecurityPortal.Infrastructure/"]
COPY ["src/shared/SecurityPortal.Contracts/SecurityPortal.Contracts.csproj", "src/shared/SecurityPortal.Contracts/"]
COPY ["Directory.Build.props", "."]
COPY ["Directory.Packages.props", "."]
COPY ["global.json", "."]

RUN dotnet restore "src/workers/SecurityPortal.Worker.SSL/SecurityPortal.Worker.SSL.csproj"
COPY . .

WORKDIR "/src/src/workers/SecurityPortal.Worker.SSL"
RUN dotnet build "SecurityPortal.Worker.SSL.csproj" -c $BUILD_CONFIGURATION -o /app/build

FROM build AS publish
ARG BUILD_CONFIGURATION=Release
RUN dotnet publish "SecurityPortal.Worker.SSL.csproj" -c $BUILD_CONFIGURATION -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "SecurityPortal.Worker.SSL.dll"]
