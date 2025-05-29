<?php
require_once 'config.php';
require_once 'auth.php';

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: ' . implode(',', Config::CORS_ORIGINS));
header('Access-Control-Allow-Methods: ' . implode(',', Config::CORS_METHODS));
header('Access-Control-Allow-Headers: ' . implode(',', Config::CORS_HEADERS));

// Gestione preflight OPTIONS
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// Rate limiting semplice
$clientIP = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
// In produzione, implementare rate limiting con Redis o database

class API {
    private $db;
    private $auth;
    
    public function __construct() {
        $this->connectDB();
        $this->auth = new AuthMiddleware($this->db);
    }
    
    private function connectDB() {
        try {
            $dsn = "mysql:host=" . Config::DB_HOST . ";dbname=" . Config::DB_NAME . ";charset=" . Config::DB_CHARSET;
            $this->db = new PDO($dsn, Config::DB_USER, Config::DB_PASS, [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false
            ]);
        } catch(PDOException $e) {
            $this->sendResponse(500, null, 'Database connection failed');
            exit();
        }
    }
    
    public function handleRequest() {
        try {
            $method = $_SERVER['REQUEST_METHOD'];
            $uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
            $segments = array_filter(explode('/', trim($uri, '/')));
            
            // Rimuovi prefissi comuni
            if (in_array($segments[0] ?? '', ['api', 'index.php'])) {
                array_shift($segments);
            }
            
            // Versioning API
            if (($segments[0] ?? '') === 'v1') {
                array_shift($segments);
            }
            
            $resource = $segments[0] ?? '';
            $action = $segments[1] ?? null;
            
            // Log della richiesta (implementare logging appropriato)
            error_log("API Request: $method $uri from " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
            
            switch ($resource) {
                case 'auth':
                    $this->handleAuth($method, $action);
                    break;
                case 'users':
                    $this->handleUsers($method, $action);
                    break;
                case 'artisti':
                    $this->handleArtisti($method, $action);
                    break;
                case 'opere':
                    $this->handleOpere($method, $action);
                    break;
                case 'opere-by-artist':
                    $this->handleOpereByArtist($method);
                    break;
                case 'opera-details':
                    $this->handleOperaDetails($method);
                    break;
                case 'artist-info':
                    $this->handleArtistInfo($method);
                    break;
                case 'opere-list':
                    $this->handleOpereList($method);
                    break;
                default:
                    $this->sendResponse(404, null, 'Endpoint not found');
            }
        } catch (Exception $e) {
            error_log("API Error: " . $e->getMessage());
            $this->sendResponse(500, null, 'Internal server error');
        }
    }
    
    // NUOVO: Gestione autenticazione
    private function handleAuth($method, $action) {
        switch ($action) {
            case 'register':
                if ($method !== 'POST') {
                    $this->sendResponse(405, null, 'Method not allowed');
                    return;
                }
                $this->register();
                break;
                
            case 'login':
                if ($method !== 'POST') {
                    $this->sendResponse(405, null, 'Method not allowed');
                    return;
                }
                $this->login();
                break;
                
            case 'logout':
                if ($method !== 'POST') {
                    $this->sendResponse(405, null, 'Method not allowed');
                    return;
                }
                $this->logout();
                break;
                
            case 'refresh':
                if ($method !== 'POST') {
                    $this->sendResponse(405, null, 'Method not allowed');
                    return;
                }
                $this->refreshToken();
                break;
                
            default:
                $this->sendResponse(404, null, 'Auth endpoint not found');
        }
    }
    
    private function register() {
        $input = $this->getInput();
        
        // Validazione input
        if (!Validator::validateRequired($input, ['name', 'email', 'password'])) {
            $this->sendResponse(400, null, 'Name, email and password are required');
            return;
        }
        
        $name = Validator::sanitizeString($input['name']);
        $email = Validator::sanitizeString($input['email']);
        $password = $input['password'];
        
        // Validazioni specifiche
        if (!Validator::validateEmail($email)) {
            $this->sendResponse(400, null, 'Invalid email format');
            return;
        }
        
        $passwordValidation = $this->auth->validatePassword($password);
        if (!$passwordValidation['valid']) {
            $this->sendResponse(400, $passwordValidation['errors'], 'Password validation failed');
            return;
        }
        
        $result = $this->auth->register($name, $email, $password);
        $this->sendResponse($result['success'] ? 201 : 400, $result, $result['message']);
    }
    
    private function login() {
        $input = $this->getInput();
        
        if (!Validator::validateRequired($input, ['email', 'password'])) {
            $this->sendResponse(400, null, 'Email and password are required');
            return;
        }
        
        $email = Validator::sanitizeString($input['email']);
        $password = $input['password'];
        
        $result = $this->auth->login($email, $password);
        $this->sendResponse($result['success'] ? 200 : 401, $result, $result['message']);
    }
    
    private function logout() {
        $input = $this->getInput();
        $token = $input['token'] ?? null;
        
        $result = $this->auth->logout($token);
        $this->sendResponse(200, $result, $result['message']);
    }
    
    private function refreshToken() {
        $input = $this->getInput();
        
        if (empty($input['token'])) {
            $this->sendResponse(400, null, 'Token is required');
            return;
        }
        
        $result = $this->auth->refreshToken($input['token']);
        $this->sendResponse($result['success'] ? 200 : 401, $result, $result['message']);
    }
    
    // MIGLIORATO: Gestione artisti con validazione
    private function handleArtisti($method, $id) {
        switch ($method) {
            case 'GET':
                if ($id) {
                    $this->getArtista($id);
                } else {
                    $this->getArtisti();
                }
                break;
            default:
                $this->sendResponse(405, null, 'Method not allowed');
        }
    }
    
    private function getArtisti() {
        try {
            $limit = min((int)($_GET['limit'] ?? Config::DEFAULT_PAGE_SIZE), Config::MAX_PAGE_SIZE);
            $offset = max(0, (int)($_GET['offset'] ?? 0));
            $search = $_GET['search'] ?? '';
            
            $sql = "SELECT IdArtista, Cognome, Nome, Pseudonimo, DataNascita, DataMorte, Stile, Nazionalita 
                    FROM Artisti";
            $params = [];
            
            if (!empty($search)) {
                $sql .= " WHERE CONCAT(Nome, ' ', Cognome) LIKE :search OR Pseudonimo LIKE :search";
                $params[':search'] = "%$search%";
            }
            
            $sql .= " ORDER BY Cognome, Nome LIMIT :limit OFFSET :offset";
            
            $stmt = $this->db->prepare($sql);
            foreach ($params as $key => $value) {
                $stmt->bindValue($key, $value);
            }
            $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
            $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
            $stmt->execute();
            
            $artisti = $stmt->fetchAll();
            
            $this->sendResponse(200, [
                'artisti' => $artisti,
                'count' => count($artisti),
                'pagination' => [
                    'limit' => $limit,
                    'offset' => $offset
                ]
            ], 'Artisti retrieved successfully');
            
        } catch(PDOException $e) {
            $this->sendResponse(500, null, 'Database error occurred');
        }
    }
    
    // NUOVO: Gestione elenco completo opere con foto e artisti
    private function handleOpereList($method) {
        if ($method !== 'GET') {
            $this->sendResponse(405, null, 'Method not allowed');
            return;
        }
        
        try {
            // Parametri di paginazione e filtri opzionali
            $limit = min((int)($_GET['limit'] ?? Config::DEFAULT_PAGE_SIZE), Config::MAX_PAGE_SIZE);
            $offset = max(0, (int)($_GET['offset'] ?? 0));
            $search = $_GET['search'] ?? '';
            $tipologia = $_GET['tipologia'] ?? '';
            $artista = $_GET['artista'] ?? '';
            
            // Query base ottimizzata con JOIN espliciti
            $sql = "SELECT DISTINCT O.NomeOpera, F.Link, A.Cognome, A.Nome, 
                           O.IdOpera, O.Tipologia, O.PeriodoRealizzazione,
                           A.IdArtista, A.Pseudonimo
                    FROM Opere O
                    INNER JOIN Creazioni C ON O.IdOpera = C.IdOpera
                    INNER JOIN Artisti A ON A.IdArtista = C.IdArtista
                    LEFT JOIN Foto F ON O.IdOpera = F.Opera";
            
            $params = [];
            $whereConditions = [];
            
            // Filtro di ricerca per nome opera
            if (!empty($search)) {
                $whereConditions[] = "O.NomeOpera LIKE :search";
                $params[':search'] = "%$search%";
            }
            
            // Filtro per tipologia
            if (!empty($tipologia)) {
                $whereConditions[] = "O.Tipologia = :tipologia";
                $params[':tipologia'] = Validator::sanitizeString($tipologia);
            }
            
            // Filtro per artista (nome o cognome)
            if (!empty($artista)) {
                $whereConditions[] = "(A.Nome LIKE :artista OR A.Cognome LIKE :artista OR A.Pseudonimo LIKE :artista)";
                $params[':artista'] = "%" . Validator::sanitizeString($artista) . "%";
            }
            
            // Aggiungi condizioni WHERE se esistono filtri
            if (!empty($whereConditions)) {
                $sql .= " WHERE " . implode(" AND ", $whereConditions);
            }
            
            // Ordinamento e paginazione
            $sql .= " ORDER BY A.Cognome, A.Nome, O.NomeOpera
                     LIMIT :limit OFFSET :offset";
            
            $stmt = $this->db->prepare($sql);
            
            // Bind dei parametri
            foreach ($params as $key => $value) {
                $stmt->bindValue($key, $value);
            }
            $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
            $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
            
            $stmt->execute();
            $results = $stmt->fetchAll();
            
            // Raggruppa i risultati per opera (nel caso ci siano più foto per opera)
            $opere = [];
            foreach ($results as $row) {
                $operaKey = $row['IdOpera'];
                
                if (!isset($opere[$operaKey])) {
                    $opere[$operaKey] = [
                        'id_opera' => $row['IdOpera'],
                        'nome_opera' => $row['NomeOpera'],
                        'tipologia' => $row['Tipologia'],
                        'periodo_realizzazione' => $row['PeriodoRealizzazione'],
                        'artista' => [
                            'id' => $row['IdArtista'],
                            'nome_completo' => Utils::formatArtistName($row['Nome'], $row['Cognome']),
                            'nome' => $row['Nome'],
                            'cognome' => $row['Cognome'],
                            'pseudonimo' => $row['Pseudonimo']
                        ],
                        'foto' => []
                    ];
                }
                
                // Aggiungi foto se presente
                if (!empty($row['Link']) && !in_array($row['Link'], $opere[$operaKey]['foto'])) {
                    $opere[$operaKey]['foto'][] = $row['Link'];
                }
            }
            
            // Converti l'array associativo in array numerico
            $opere = array_values($opere);
            
            // Query per il totale (per la paginazione)
            $countSql = "SELECT COUNT(DISTINCT O.IdOpera) as total
                        FROM Opere O
                        INNER JOIN Creazioni C ON O.IdOpera = C.IdOpera
                        INNER JOIN Artisti A ON A.IdArtista = C.IdArtista";
            
            if (!empty($whereConditions)) {
                $countSql .= " WHERE " . implode(" AND ", $whereConditions);
            }
            
            $countStmt = $this->db->prepare($countSql);
            foreach ($params as $key => $value) {
                if ($key !== ':limit' && $key !== ':offset') {
                    $countStmt->bindValue($key, $value);
                }
            }
            $countStmt->execute();
            $totalCount = $countStmt->fetch()['total'];
            
            $this->sendResponse(200, [
                'opere' => $opere,
                'count' => count($opere),
                'total_count' => (int)$totalCount,
                'pagination' => [
                    'limit' => $limit,
                    'offset' => $offset,
                    'has_more' => ($offset + $limit) < $totalCount
                ],
                'filters_applied' => Utils::filterEmptyValues([
                    'search' => $search,
                    'tipologia' => $tipologia,
                    'artista' => $artista
                ])
            ], 'Opere list retrieved successfully');
            
        } catch(PDOException $e) {
            error_log("Database error in handleOpereList: " . $e->getMessage());
            $this->sendResponse(500, null, 'Database error occurred');
        }
    }
    
    // Metodo esistente handleOpere (per compatibilità)
    private function handleOpere($method, $action) {
        switch ($method) {
            case 'GET':
                // Redirect al nuovo endpoint per l'elenco completo
                $this->handleOpereList($method);
                break;
            default:
                $this->sendResponse(405, null, 'Method not allowed');
        }
    }
    
    // MIGLIORATO: Con validazione parametri
    private function handleOpereByArtist($method) {
        if ($method !== 'GET') {
            $this->sendResponse(405, null, 'Method not allowed');
            return;
        }
        
        $nome = $_GET['nome'] ?? '';
        $cognome = $_GET['cognome'] ?? '';
        
        // Validazione parametri
        if (empty($nome) || empty($cognome)) {
            $this->sendResponse(400, null, 'Nome and cognome parameters are required');
            return;
        }
        
        // Sanitizzazione
        $nome = Validator::sanitizeString($nome);
        $cognome = Validator::sanitizeString($cognome);
        
        // Validazione formato
        if (!Validator::validateArtistName($nome, $cognome)) {
            $this->sendResponse(400, null, 'Invalid artist name format');
            return;
        }
        
        try {
            $stmt = $this->db->prepare("
                SELECT O.NomeOpera, O.Tipologia, O.PeriodoRealizzazione, A.Nome, A.Cognome 
                FROM Artisti A 
                INNER JOIN Creazioni C ON C.IdArtista = A.IdArtista 
                INNER JOIN Opere O ON C.IdOpera = O.IdOpera 
                WHERE A.Nome = :nome AND A.Cognome = :cognome
                ORDER BY O.PeriodoRealizzazione
            ");
            
            $stmt->bindParam(':nome', $nome);
            $stmt->bindParam(':cognome', $cognome);
            $stmt->execute();
            
            $opere = $stmt->fetchAll();
            
            if (empty($opere)) {
                $this->sendResponse(404, null, 'No opere found for this artist');
                return;
            }
            
            $this->sendResponse(200, [
                'artist' => Utils::formatArtistName($nome, $cognome),
                'opere' => $opere,
                'count' => count($opere)
            ], 'Opere retrieved successfully');
            
        } catch(PDOException $e) {
            $this->sendResponse(500, null, 'Database error occurred');
        }
    }
    
    // MIGLIORATO: Con validazione e sanitizzazione
    private function handleOperaDetails($method) {
        if ($method !== 'GET') {
            $this->sendResponse(405, null, 'Method not allowed');
            return;
        }
        
        $nomeOpera = $_GET['nome'] ?? '';
        
        if (empty($nomeOpera)) {
            $this->sendResponse(400, null, 'Nome parameter is required');
            return;
        }
        
        $nomeOpera = Validator::sanitizeString($nomeOpera);
        
        if (!Validator::validateOperaName($nomeOpera)) {
            $this->sendResponse(400, null, 'Invalid opera name format');
            return;
        }
        
        try {
            $stmt = $this->db->prepare("
                SELECT DISTINCT O.*, 
                       GROUP_CONCAT(DISTINCT F.Link) as FotoLinks,
                       GROUP_CONCAT(DISTINCT M.Nome) as MaterialiNomi
                FROM Opere O
                LEFT JOIN Foto F ON O.IdOpera = F.Opera
                LEFT JOIN MaterialiOpere MO ON O.IdOpera = MO.IdOpera
                LEFT JOIN Materiali M ON M.IdMateriale = MO.IdMateriale
                WHERE O.NomeOpera = :nome_opera
                GROUP BY O.IdOpera
            ");
            
            $stmt->bindParam(':nome_opera', $nomeOpera);
            $stmt->execute();
            
            $result = $stmt->fetch();
            
            if (!$result) {
                $this->sendResponse(404, null, 'Opera not found');
                return;
            }
            
            // Formatta la risposta
            $opera = [
                'id' => $result['IdOpera'],
                'nome' => $result['NomeOpera'],
                'descrizione' => $result['Descrizione'],
                'periodo' => $result['PeriodoRealizzazione'],
                'tipologia' => $result['Tipologia'],
                'altezza' => $result['Altezza'],
                'proprietario' => $result['Proprietario'],
                'detentore_diritti' => $result['DetentoreDiritti'],
                'link_video' => $result['LinkVideo'],
                'foto' => $result['FotoLinks'] ? explode(',', $result['FotoLinks']) : [],
                'materiali' => $result['MaterialiNomi'] ? explode(',', $result['MaterialiNomi']) : []
            ];
            
            $this->sendResponse(200, $opera, 'Opera details retrieved successfully');
            
        } catch(PDOException $e) {
            $this->sendResponse(500, null, 'Database error occurred');
        }
    }
    
    // MIGLIORATO: Con validazione completa
    private function handleArtistInfo($method) {
        if ($method !== 'GET') {
            $this->sendResponse(405, null, 'Method not allowed');
            return;
        }
        
        $nome = $_GET['nome'] ?? '';
        $cognome = $_GET['cognome'] ?? '';
        $lingua = $_GET['lingua'] ?? Config::DEFAULT_LANGUAGE;
        
        if (empty($nome) || empty($cognome)) {
            $this->sendResponse(400, null, 'Nome and cognome parameters are required');
            return;
        }
        
        // Sanitizzazione
        $nome = Validator::sanitizeString($nome);
        $cognome = Validator::sanitizeString($cognome);
        $lingua = Validator::sanitizeString($lingua);
        
        // Validazioni
        if (!Validator::validateArtistName($nome, $cognome)) {
            $this->sendResponse(400, null, 'Invalid artist name format');
            return;
        }
        
        if (!Validator::validateLanguage($lingua)) {
            $this->sendResponse(400, null, 'Unsupported language');
            return;
        }
        
        try {
            $stmt = $this->db->prepare("
                SELECT A.*, B.Testo, B.Lingua 
                FROM Artisti A
                LEFT JOIN Biografie B ON A.IdArtista = B.IdArtista AND B.Lingua = :lingua
                WHERE A.Nome = :nome AND A.Cognome = :cognome
            ");
            
            $stmt->bindParam(':nome', $nome);
            $stmt->bindParam(':cognome', $cognome);
            $stmt->bindParam(':lingua', $lingua);
            $stmt->execute();
            
            $result = $stmt->fetch();
            
            if (!$result) {
                $this->sendResponse(404, null, 'Artist not found');
                return;
            }
            
            $artist = [
                'id' => $result['IdArtista'],
                'nome_completo' => Utils::formatArtistName($result['Nome'], $result['Cognome']),
                'pseudonimo' => $result['Pseudonimo'],
                'date_range' => Utils::formatDateRange($result['DataNascita'], $result['DataMorte']),
                'nascita' => [
                    'data' => $result['DataNascita'],
                    'luogo' => $result['LuogoNascita']
                ],
                'morte' => [
                    'data' => $result['DataMorte'],
                    'luogo' => $result['LuogoMorte']
                ],
                'stile' => $result['Stile'],
                'nazionalita' => $result['Nazionalita'],
                'biografia' => $result['Testo'] ? [
                    'lingua' => $result['Lingua'],
                    'testo' => $result['Testo']
                ] : null
            ];
            
            $this->sendResponse(200, $artist, 'Artist information retrieved successfully');
            
        } catch(PDOException $e) {
            $this->sendResponse(500, null, 'Database error occurred');
        }
    }
    
    // Metodi di utilità esistenti con miglioramenti...
    private function handleUsers($method, $id) {
        // Richiede autenticazione per gli endpoint users
        $user = $this->auth->authenticate();
        if (!$user) {
            return; // authenticate() ha già inviato la risposta di errore
        }
        
        // Resto del codice esistente...
    }
    
    private function getInput() {
        $input = json_decode(file_get_contents('php://input'), true);
        
        if (json_last_error() !== JSON_ERROR_NONE) {
            $this->sendResponse(400, null, 'Invalid JSON format');
            return [];
        }
        
        return $input ?? [];
    }
    
    private function sendResponse($code, $data = null, $message = null) {
        http_response_code($code);
        
        $response = Utils::formatResponse(
            $code >= 400 ? 'error' : 'success',
            $data,
            $message
        );
        
        echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
        exit();
    }
}

// Avvio dell'API con gestione errori migliorata
try {
    session_start();
    $api = new API();
    $api->handleRequest();
} catch (Throwable $e) {
    error_log("Critical API Error: " . $e->getMessage() . " in " . $e->getFile() . ":" . $e->getLine());
    http_response_code(500);
    echo json_encode(Utils::formatResponse('error', null, 'Internal server error'));
}
?>