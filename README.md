#Endpoint
# API MiraDB - Elenco Completo Endpoints

## Base URL
```
http://localhost/api/
```
oppure
```
http://localhost/index.php/
```

## 1. ENDPOINTS AUTENTICAZIONE

### 1.1 Registrazione Utente
**Endpoint:** `POST /auth/register`

**Descrizione:** Registra un nuovo utente nel sistema

**Request Body:**
```json
{
    "name": "Mario Rossi",
    "email": "mario.rossi@example.com",
    "password": "Password123!"
}
```

**Response (201):**
```json
{
    "status": "success",
    "data": {
        "success": true,
        "message": "User registered successfully",
        "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
        "user": {
            "id": 4,
            "name": "Mario Rossi",
            "email": "mario.rossi@example.com"
        },
        "expires_in": 3600
    },
    "message": "User registered successfully",
    "timestamp": "2025-05-29 10:30:00"
}
```

**Validazioni:**
- Nome, email e password obbligatori
- Email deve essere valida
- Password deve contenere: almeno 8 caratteri, una maiuscola, una minuscola, un numero, un carattere speciale

### 1.2 Login
**Endpoint:** `POST /auth/login`

**Request Body:**
```json
{
    "email": "mario.rossi@example.com",
    "password": "Password123!"
}
```

**Response (200):**
```json
{
    "status": "success",
    "data": {
        "success": true,
        "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
        "user": {
            "id": 4,
            "name": "Mario Rossi",
            "email": "mario.rossi@example.com"
        },
        "expires_in": 3600
    },
    "timestamp": "2025-05-29 10:35:00"
}
```

### 1.3 Logout
**Endpoint:** `POST /auth/logout`

**Request Body (opzionale):**
```json
{
    "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
}
```

**Response (200):**
```json
{
    "status": "success",
    "data": {
        "success": true,
        "message": "Logged out successfully"
    },
    "message": "Logged out successfully",
    "timestamp": "2025-05-29 10:40:00"
}
```

### 1.4 Refresh Token
**Endpoint:** `POST /auth/refresh`

**Request Body:**
```json
{
    "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
}
```

**Response (200):**
```json
{
    "status": "success",
    "data": {
        "success": true,
        "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
        "expires_in": 3600
    },
    "timestamp": "2025-05-29 10:45:00"
}
```

## 2. ENDPOINTS ARTISTI

### 2.1 Lista Artisti
**Endpoint:** `GET /artisti`

**Parametri Query (opzionali):**
- `limit`: Numero risultati per pagina (default: 10, max: 100)
- `offset`: Punto di partenza per la paginazione (default: 0)
- `search`: Termine di ricerca per nome, cognome o pseudonimo

**Esempi:**
```
GET /artisti
GET /artisti?limit=20&offset=0
GET /artisti?search=Leonardo
GET /artisti?search=Vinci&limit=5
```

**Response (200):**
```json
{
    "status": "success",
    "data": {
        "artisti": [
            {
                "IdArtista": 1,
                "Cognome": "da Vinci",
                "Nome": "Leonardo",
                "Pseudonimo": "Leonardo",
                "DataNascita": "1452-04-15",
                "DataMorte": "1519-05-02",
                "Stile": "Rinascimento",
                "Nazionalita": "Italiana"
            },
            {
                "IdArtista": 2,
                "Cognome": "Buonarroti",
                "Nome": "Michelangelo",
                "Pseudonimo": "Michelangelo",
                "DataNascita": "1475-03-06",
                "DataMorte": "1564-02-18",
                "Stile": "Rinascimento",
                "Nazionalita": "Italiana"
            }
        ],
        "count": 2,
        "pagination": {
            "limit": 10,
            "offset": 0
        }
    },
    "message": "Artisti retrieved successfully",
    "timestamp": "2025-05-29 11:00:00"
}
```

### 2.2 Informazioni Specifiche Artista
**Endpoint:** `GET /artist-info`

**Parametri Query (obbligatori):**
- `nome`: Nome dell'artista
- `cognome`: Cognome dell'artista
- `lingua`: Lingua per la biografia (opzionale, default: 'it')

**Esempi:**
```
GET /artist-info?nome=Leonardo&cognome=da%20Vinci
GET /artist-info?nome=Leonardo&cognome=da%20Vinci&lingua=en
```

**Response (200):**
```json
{
    "status": "success",
    "data": {
        "id": 1,
        "nome_completo": "da Vinci, Leonardo",
        "pseudonimo": "Leonardo",
        "date_range": "(1452 - 1519)",
        "nascita": {
            "data": "1452-04-15",
            "luogo": "Vinci, Firenze"
        },
        "morte": {
            "data": "1519-05-02",
            "luogo": "Amboise, Francia"
        },
        "stile": "Rinascimento",
        "nazionalita": "Italiana",
        "biografia": {
            "lingua": "it",
            "testo": "Leonardo da Vinci è stato un pittore, ingegnere e scienziato italiano..."
        }
    },
    "message": "Artist information retrieved successfully",
    "timestamp": "2025-05-29 11:05:00"
}
```

## 3. ENDPOINTS OPERE

### 3.1 Lista Completa Opere
**Endpoint:** `GET /opere-list`

**Parametri Query (opzionali):**
- `limit`: Numero risultati per pagina (default: 10, max: 100)
- `offset`: Punto di partenza per la paginazione (default: 0)
- `search`: Ricerca per nome opera
- `tipologia`: Filtro per tipologia opera
- `artista`: Filtro per nome/cognome/pseudonimo artista

**Esempi:**
```
GET /opere-list
GET /opere-list?limit=20&offset=10
GET /opere-list?search=Gioconda
GET /opere-list?tipologia=Pittura
GET /opere-list?artista=Leonardo
GET /opere-list?tipologia=Scultura&artista=Michelangelo&limit=5
```

**Response (200):**
```json
{
    "status": "success",
    "data": {
        "opere": [
            {
                "id_opera": 1,
                "nome_opera": "La Gioconda",
                "tipologia": "Pittura",
                "periodo_realizzazione": "1503-1519",
                "artista": {
                    "id": 1,
                    "nome_completo": "da Vinci, Leonardo",
                    "nome": "Leonardo",
                    "cognome": "da Vinci",
                    "pseudonimo": "Leonardo"
                },
                "foto": [
                    "https://example.com/foto1.jpg",
                    "https://example.com/foto2.jpg"
                ]
            },
            {
                "id_opera": 2,
                "nome_opera": "David",
                "tipologia": "Scultura",
                "periodo_realizzazione": "1501-1504",
                "artista": {
                    "id": 2,
                    "nome_completo": "Buonarroti, Michelangelo",
                    "nome": "Michelangelo",
                    "cognome": "Buonarroti",
                    "pseudonimo": "Michelangelo"
                },
                "foto": [
                    "https://example.com/david1.jpg"
                ]
            }
        ],
        "count": 2,
        "total_count": 15,
        "pagination": {
            "limit": 10,
            "offset": 0,
            "has_more": true
        },
        "filters_applied": {
            "search": "",
            "tipologia": "",
            "artista": ""
        }
    },
    "message": "Opere list retrieved successfully",
    "timestamp": "2025-05-29 11:10:00"
}
```

### 3.2 Opere per Artista Specifico
**Endpoint:** `GET /opere-by-artist`

**Parametri Query (obbligatori):**
- `nome`: Nome dell'artista
- `cognome`: Cognome dell'artista

**Esempi:**
```
GET /opere-by-artist?nome=Leonardo&cognome=da%20Vinci
GET /opere-by-artist?nome=Michelangelo&cognome=Buonarroti
```

**Response (200):**
```json
{
    "status": "success",
    "data": {
        "artist": "da Vinci, Leonardo",
        "opere": [
            {
                "NomeOpera": "La Gioconda",
                "Tipologia": "Pittura",
                "PeriodoRealizzazione": "1503-1519",
                "Nome": "Leonardo",
                "Cognome": "da Vinci"
            },
            {
                "NomeOpera": "L'Ultima Cena",
                "Tipologia": "Affresco",
                "PeriodoRealizzazione": "1495-1498",
                "Nome": "Leonardo",
                "Cognome": "da Vinci"
            }
        ],
        "count": 2
    },
    "message": "Opere retrieved successfully",
    "timestamp": "2025-05-29 11:15:00"
}
```

### 3.3 Dettagli Opera Specifica
**Endpoint:** `GET /opera-details`

**Parametri Query (obbligatori):**
- `nome`: Nome dell'opera

**Esempi:**
```
GET /opera-details?nome=La%20Gioconda
GET /opera-details?nome=David
```

**Response (200):**
```json
{
    "status": "success",
    "data": {
        "id": 1,
        "nome": "La Gioconda",
        "descrizione": "Ritratto di donna realizzato da Leonardo da Vinci...",
        "periodo": "1503-1519",
        "tipologia": "Pittura",
        "altezza": 77,
        "proprietario": "Museo del Louvre",
        "detentore_diritti": "Repubblica Francese",
        "link_video": "https://youtube.com/watch?v=example",
        "foto": [
            "https://example.com/gioconda1.jpg",
            "https://example.com/gioconda2.jpg"
        ],
        "materiali": [
            "Olio su tavola",
            "Legno di pioppo"
        ]
    },
    "message": "Opera details retrieved successfully",
    "timestamp": "2025-05-29 11:20:00"
}
```

## 4. HEADERS RICHIESTI

### Per Endpoint Pubblici
```
Content-Type: application/json
```

### Per Endpoint Autenticati
```
Content-Type: application/json
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
```

## 5. CODICI DI STATO HTTP

- **200 OK**: Richiesta completata con successo
- **201 Created**: Risorsa creata con successo (registrazione)
- **400 Bad Request**: Parametri mancanti o non validi
- **401 Unauthorized**: Token mancante o non valido
- **404 Not Found**: Risorsa non trovata
- **405 Method Not Allowed**: Metodo HTTP non supportato
- **500 Internal Server Error**: Errore interno del server

## 6. ESEMPI DI ERRORE

### Parametri Mancanti (400)
```json
{
    "status": "error",
    "message": "Nome and cognome parameters are required",
    "timestamp": "2025-05-29 11:25:00"
}
```

### Risorsa Non Trovata (404)
```json
{
    "status": "error",
    "message": "Artist not found",
    "timestamp": "2025-05-29 11:26:00"
}
```

### Errore Autenticazione (401)
```json
{
    "error": "Unauthorized",
    "message": "Authorization header missing"
}
```

## 7. NOTE IMPORTANTI

1. **Validazione Parametri**: Tutti i parametri vengono sanitizzati per prevenire attacchi XSS
2. **Paginazione**: Utilizzare `limit` e `offset` per gestire grandi dataset
3. **Rate Limiting**: Configurato per massimo 1000 richieste/ora per IP
4. **CORS**: Configurato per accettare richieste da qualsiasi origine (modificare in produzione)
5. **Lingue Supportate**: it, en, es, fr per biografie e descrizioni
6. **Token JWT**: Scadenza di 1 ora (3600 secondi)

## 8. CONFIGURAZIONE DATABASE

Il database MiraDB deve essere configurato con le seguenti tabelle:
- Artisti
- Biografie
- Opere
- DescrizioniOpere
- Creazioni
- Posizioni
- Itinerari
- Percorsi
- Materiali
- MaterialiOpere
- Foto
- Soggetti
- SoggettiRappresentati

## 9. ESEMPI DI UTILIZZO CON CURL

### Registrazione
```bash
curl -X POST http://localhost/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"name":"Mario Rossi","email":"mario@example.com","password":"Password123!"}'
```

### Login
```bash
curl -X POST http://localhost/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"mario@example.com","password":"Password123!"}'
```

### Lista Artisti
```bash
curl -X GET "http://localhost/api/artisti?limit=5&search=Leonardo"
```

### Dettagli Opera
```bash
curl -X GET "http://localhost/api/opera-details?nome=La%20Gioconda"
```
