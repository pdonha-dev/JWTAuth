FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
USER root
RUN apt-get update \
	&& apt-get install -y --no-install-recommends curl \
	&& rm -rf /var/lib/apt/lists/*
USER app
WORKDIR /app
EXPOSE 8080
EXPOSE 8443

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
ARG BUILD_CONFIGURATION=Release
WORKDIR /src
COPY ["JWTAuth/JWTAuth.csproj", "JWTAuth/"]
COPY ["JWTAuth.Db/JWTAuth.Db.csproj", "JWTAuth.Db/"]
COPY ["JWTAuth.Entities/JWTAuth.Entities.csproj", "JWTAuth.Entities/"]
COPY ["JWTAuth.Core/JWTAuth.Core.csproj", "JWTAuth.Core/"]
RUN dotnet restore "./JWTAuth/JWTAuth.csproj"
COPY . .
WORKDIR "/src/JWTAuth"
RUN dotnet build "./JWTAuth.csproj" -c $BUILD_CONFIGURATION -o /app/build

FROM build AS publish
ARG BUILD_CONFIGURATION=Release
RUN dotnet publish "./JWTAuth.csproj" -c $BUILD_CONFIGURATION -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "JWTAuth.dll"]