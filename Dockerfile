# ---- Build stage ----
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Copia todo (incluye libs/Portable.Licensing.dll y .csproj)
COPY . .

# Restaura y publica
RUN dotnet restore ./EarthLicServer.csproj
RUN dotnet publish ./EarthLicServer.csproj -c Release -o /app/publish

# ---- Runtime stage ----
FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app
COPY --from=build /app/publish .

# Render asigna $PORT; nuestro Program.cs ya lo respeta,
# pero dejamos este env por si acaso.
ENV ASPNETCORE_URLS=http://0.0.0.0:${PORT}

# Inicia el servidor
CMD ["dotnet", "EarthLicServer.dll"]
