# Fortoes_Codrin_1411B_Proiect_Licenta

# OV1 — Note rulare

## Pornire stack

```bash
# 1. OpenVAS
cd openvas-env && docker compose up -d

# 2. OV1 + Jenkins
cd openvas-service && docker compose up -d
```

## Health check

```bash
curl http://localhost:8081/health
```

## Gaseste IP-ul Metasploitable2

```bash
docker inspect metasploitable | grep IPAddress
```

## Porneste o scanare (din Jenkins)

`http://localhost:8080` → **ov1-scan** → **Build with Parameters**

| Parametru | Valoare |
|---|---|
| TARGET_IP | IP-ul din comanda de mai sus |
| TARGET_HOST | `metasploitable2` |
| ASSET_ID | `asset-metasploitable-01` |

## Verifica status scanare

```bash
curl http://localhost:8081/scans/<scan_id> \
  -H "Authorization: Bearer ov1-api-token"
```

## Verifica rezultate + MrBenny push

```bash
curl http://localhost:8081/scans/<scan_id>/results \
  -H "Authorization: Bearer ov1-api-token"
```

## Verifica journal

```bash
curl http://localhost:8081/journal \
  -H "Authorization: Bearer ov1-api-token"
```

## Jenkins UI

- `http://localhost:8080/job/ov1-pipeline` — CI (teste automate la fiecare commit)
- `http://localhost:8080/job/ov1-scan` — pornire scanare manuala

## OpenVAS UI

```
https://127.0.0.1:9392
```