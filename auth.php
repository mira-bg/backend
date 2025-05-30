<?php
require_once 'config.php';

// Avvia la sessione all'inizio di ogni richiesta
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

class AuthMiddleware {
    private $db;
    
    public function __construct($db) {
        $this->db = $db;
    }
    
    // Controlla se l'utente è autenticato tramite sessione
    public function authenticate() {
        if (!isset($_SESSION['current_user'])) {
            $this->sendUnauthorized('Not authenticated');
            return false;
        }
        return $_SESSION['current_user'];
    }

    // Login: verifica credenziali e salva l'utente in sessione
    public function login($email, $password) {
        try {
            $stmt = $this->db->prepare("SELECT IdUtente, Username, Email, Password, Ruolo FROM Utenti WHERE Email = :email");
            $stmt->bindParam(':email', $email);
            $stmt->execute();

            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$user || !Utils::verifyPassword($password, $user['Password'])) {
                return ['success' => false, 'message' => 'Invalid credentials'];
            }

            // Salva l'utente in sessione
            $_SESSION['current_user'] = [
                'id' => $user['IdUtente'],
                'username' => $user['Username'],
                'email' => $user['Email'],
                'ruolo' => $user['Ruolo']
            ];

            return [
                'success' => true,
                'user' => $_SESSION['current_user'],
                'message' => 'Login successful'
            ];

        } catch (PDOException $e) {
            return ['success' => false, 'message' => 'Database error'];
        }
    }

    // Registrazione: crea nuovo utente e salva in sessione
    public function register($name, $email, $password) {
        try {
            // Verifica se l'email esiste già
            $stmt = $this->db->prepare("SELECT IdUtente FROM Utenti WHERE Email = :email");
            $stmt->bindParam(':email', $email);
            $stmt->execute();

            if ($stmt->fetch()) {
                return ['success' => false, 'message' => 'Email already exists'];
            }

            $hashedPassword = Utils::hashPassword($password);

            // Inserisce il nuovo utente
            $stmt = $this->db->prepare("INSERT INTO Utenti (Username, Email, Password) VALUES (:username, :email, :password)");
            $stmt->bindParam(':username', $name);
            $stmt->bindParam(':email', $email);
            $stmt->bindParam(':password', $hashedPassword);
            $stmt->execute();

            $userId = $this->db->lastInsertId();

            // Salva l'utente in sessione
            $_SESSION['current_user'] = [
                'id' => $userId,
                'username' => $name,
                'email' => $email,
                'ruolo' => 'user'
            ];

            return [
                'success' => true,
                'message' => 'User registered successfully',
                'user' => $_SESSION['current_user']
            ];

        } catch (PDOException $e) {
            return ['success' => false, 'message' => 'Database error: ' . $e->getMessage()];
        }
    }

    // Logout: distrugge la sessione
    public function logout() {
        session_unset();
        session_destroy();
        return ['success' => true, 'message' => 'Logged out successfully'];
    }

    // Questi metodi non servono più senza token, ma li lasciamo per compatibilità
    public function refreshToken($oldToken) {
        return ['success' => false, 'message' => 'Not implemented: session-based auth does not use tokens'];
    }
    
    public function validatePassword($password) {
        $errors = [];
        if (strlen($password) < 8) {
            $errors[] = 'Password must be at least 8 characters long';
        }
        if (!preg_match('/[A-Z]/', $password)) {
            $errors[] = 'Password must contain at least one uppercase letter';
        }
        if (!preg_match('/[a-z]/', $password)) {
            $errors[] = 'Password must contain at least one lowercase letter';
        }
        if (!preg_match('/[0-9]/', $password)) {
            $errors[] = 'Password must contain at least one number';
        }
        if (!preg_match('/[^A-Za-z0-9]/', $password)) {
            $errors[] = 'Password must contain at least one special character';
        }
        return empty($errors) ? ['valid' => true] : ['valid' => false, 'errors' => $errors];
    }
    
    public function validateEmail($email) {
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return ['valid' => false, 'error' => 'Invalid email format'];
        }
        return ['valid' => true];
    }
    
    private function sendUnauthorized($message) {
        http_response_code(401);
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Unauthorized', 'message' => $message]);
    }
}

class Utils {
    public static function hashPassword($password) {
        return password_hash($password, PASSWORD_DEFAULT);
    }
    
    public static function verifyPassword($password, $hash) {
        return password_verify($password, $hash);
    }
    
    public static function generateRandomToken($length = 32) {
        return bin2hex(random_bytes($length));
    }
    
    public static function sanitizeInput($input) {
        return htmlspecialchars(strip_tags(trim($input)), ENT_QUOTES, 'UTF-8');
    }
}

// Esempio di utilizzo del middleware
class ApiController {
    private $auth;
    private $db;
    
    public function __construct($db) {
        $this->db = $db;
        $this->auth = new AuthMiddleware($db);
    }
    
    public function handleRequest() {
        $method = $_SERVER['REQUEST_METHOD'];
        $uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
        
        switch ($uri) {
            case '/api/register':
                if ($method === 'POST') {
                    $this->register();
                } else {
                    $this->methodNotAllowed();
                }
                break;
                
            case '/api/login':
                if ($method === 'POST') {
                    $this->login();
                } else {
                    $this->methodNotAllowed();
                }
                break;
                
            case '/api/logout':
                if ($method === 'POST') {
                    $this->logout();
                } else {
                    $this->methodNotAllowed();
                }
                break;
                
            case '/api/profile':
                if ($method === 'GET') {
                    $this->getProfile();
                } else {
                    $this->methodNotAllowed();
                }
                break;
                
            default:
                $this->notFound();
                break;
        }
    }
    
    private function register() {
        $input = json_decode(file_get_contents('php://input'), true);
        
        $name = Utils::sanitizeInput($input['name'] ?? '');
        $email = Utils::sanitizeInput($input['email'] ?? '');
        $password = $input['password'] ?? '';
        
        if (empty($name) || empty($email) || empty($password)) {
            $this->sendResponse(['error' => 'All fields are required'], 400);
            return;
        }
        
        $emailValidation = $this->auth->validateEmail($email);
        if (!$emailValidation['valid']) {
            $this->sendResponse(['error' => $emailValidation['error']], 400);
            return;
        }
        
        $passwordValidation = $this->auth->validatePassword($password);
        if (!$passwordValidation['valid']) {
            $this->sendResponse(['error' => 'Password validation failed', 'details' => $passwordValidation['errors']], 400);
            return;
        }
        
        $result = $this->auth->register($name, $email, $password);
        $this->sendResponse($result, $result['success'] ? 201 : 400);
    }
    
    private function login() {
        $input = json_decode(file_get_contents('php://input'), true);
        
        $email = Utils::sanitizeInput($input['email'] ?? '');
        $password = $input['password'] ?? '';
        
        if (empty($email) || empty($password)) {
            $this->sendResponse(['error' => 'Email and password are required'], 400);
            return;
        }
        
        $result = $this->auth->login($email, $password);
        $this->sendResponse($result, $result['success'] ? 200 : 401);
    }
    
    private function logout() {
        $result = $this->auth->logout();
        $this->sendResponse($result);
    }
    
    private function getProfile() {
        $user = $this->auth->authenticate();
        if (!$user) {
            return; // authenticate() already sent the error response
        }
        $this->sendResponse(['user' => $user]);
    }
    
    private function sendResponse($data, $statusCode = 200) {
        http_response_code($statusCode);
        header('Content-Type: application/json');
        echo json_encode($data);
    }
    
    private function methodNotAllowed() {
        $this->sendResponse(['error' => 'Method not allowed'], 405);
    }
    
    private function notFound() {
        $this->sendResponse(['error' => 'Endpoint not found'], 404);
    }
}

?>