<?php
require_once 'config.php';

class JWT {
    private static function base64UrlEncode($data) {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
    
    private static function base64UrlDecode($data) {
        return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));
    }
    
    public static function encode($payload, $secret) {
        $header = json_encode(['typ' => 'JWT', 'alg' => 'HS256']);
        $payload = json_encode($payload);
        
        $headerEncoded = self::base64UrlEncode($header);
        $payloadEncoded = self::base64UrlEncode($payload);
        
        $signature = hash_hmac('sha256', $headerEncoded . '.' . $payloadEncoded, $secret, true);
        $signatureEncoded = self::base64UrlEncode($signature);
        
        return $headerEncoded . '.' . $payloadEncoded . '.' . $signatureEncoded;
    }
    
    public static function decode($jwt, $secret) {
        $parts = explode('.', $jwt);
        
        if (count($parts) !== 3) {
            throw new Exception('Invalid JWT format');
        }
        
        list($headerEncoded, $payloadEncoded, $signatureEncoded) = $parts;
        
        $signature = self::base64UrlDecode($signatureEncoded);
        $expectedSignature = hash_hmac('sha256', $headerEncoded . '.' . $payloadEncoded, $secret, true);
        
        if (!hash_equals($signature, $expectedSignature)) {
            throw new Exception('Invalid JWT signature');
        }
        
        $payload = json_decode(self::base64UrlDecode($payloadEncoded), true);
        
        if (isset($payload['exp']) && $payload['exp'] < time()) {
            throw new Exception('JWT token expired');
        }
        
        return $payload;
    }
}

class AuthMiddleware {
    private $db;
    
    public function __construct($db) {
        $this->db = $db;
    }
    
    public function authenticate() {
        $headers = getallheaders();
        
        if (!isset($headers['Authorization'])) {
            $this->sendUnauthorized('Authorization header missing');
            return false;
        }
        
        $authHeader = $headers['Authorization'];
        
        if (!preg_match('/Bearer\s+(.*)$/i', $authHeader, $matches)) {
            $this->sendUnauthorized('Invalid authorization format');
            return false;
        }
        
        $token = $matches[1];
        
        try {
            $payload = JWT::decode($token, Config::JWT_SECRET);
            
            // Verifica se l'utente esiste ancora
            $stmt = $this->db->prepare("SELECT id, name, email FROM users WHERE id = :id");
            $stmt->bindParam(':id', $payload['user_id'], PDO::PARAM_INT);
            $stmt->execute();
            
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$user) {
                $this->sendUnauthorized('User not found');
                return false;
            }
            
            // Salva i dati dell'utente corrente
            $_SESSION['current_user'] = $user;
            
            return $user;
            
        } catch (Exception $e) {
            $this->sendUnauthorized('Invalid token: ' . $e->getMessage());
            return false;
        }
    }
    
    public function login($email, $password) {
        try {
            $stmt = $this->db->prepare("SELECT id, name, email, password FROM users WHERE email = :email");
            $stmt->bindParam(':email', $email);
            $stmt->execute();
            
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$user || !Utils::verifyPassword($password, $user['password'])) {
                return ['success' => false, 'message' => 'Invalid credentials'];
            }
            
            // Genera il token JWT
            $payload = [
                'user_id' => $user['id'],
                'email' => $user['email'],
                'iat' => time(),
                'exp' => time() + Config::JWT_EXPIRE_TIME
            ];
            
            $token = JWT::encode($payload, Config::JWT_SECRET);
            
            // Salva il token nel database (opzionale)
            $stmt = $this->db->prepare("INSERT INTO api_tokens (user_id, token, expires_at) VALUES (:user_id, :token, :expires_at)");
            $stmt->bindParam(':user_id', $user['id'], PDO::PARAM_INT);
            $stmt->bindParam(':token', $token);
            $stmt->bindParam(':expires_at', date('Y-m-d H:i:s', time() + Config::JWT_EXPIRE_TIME));
            $stmt->execute();
            
            return [
                'success' => true,
                'token' => $token,
                'user' => [
                    'id' => $user['id'],
                    'name' => $user['name'],
                    'email' => $user['email']
                ],
                'expires_in' => Config::JWT_EXPIRE_TIME
            ];
            
        } catch (PDOException $e) {
            return ['success' => false, 'message' => 'Database error'];
        }
    }
    
    public function register($name, $email, $password) {
        try {
            // Verifica se l'email esiste già
            $stmt = $this->db->prepare("SELECT id FROM users WHERE email = :email");
            $stmt->bindParam(':email', $email);
            $stmt->execute();
            
            if ($stmt->fetch()) {
                return ['success' => false, 'message' => 'Email already exists'];
            }
            
            // Hash della password
            $hashedPassword = Utils::hashPassword($password);
            
            // Inserisce il nuovo utente
            $stmt = $this->db->prepare("INSERT INTO users (name, email, password, created_at) VALUES (:name, :email, :password, NOW())");
            $stmt->bindParam(':name', $name);
            $stmt->bindParam(':email', $email);
            $stmt->bindParam(':password', $hashedPassword);
            $stmt->execute();
            
            $userId = $this->db->lastInsertId();
            
            // Genera il token JWT per il nuovo utente
            $payload = [
                'user_id' => $userId,
                'email' => $email,
                'iat' => time(),
                'exp' => time() + Config::JWT_EXPIRE_TIME
            ];
            
            $token = JWT::encode($payload, Config::JWT_SECRET);
            
            // Salva il token nel database
            $stmt = $this->db->prepare("INSERT INTO api_tokens (user_id, token, expires_at) VALUES (:user_id, :token, :expires_at)");
            $stmt->bindParam(':user_id', $userId, PDO::PARAM_INT);
            $stmt->bindParam(':token', $token);
            $stmt->bindParam(':expires_at', date('Y-m-d H:i:s', time() + Config::JWT_EXPIRE_TIME));
            $stmt->execute();
            
            return [
                'success' => true,
                'message' => 'User registered successfully',
                'token' => $token,
                'user' => [
                    'id' => $userId,
                    'name' => $name,
                    'email' => $email
                ],
                'expires_in' => Config::JWT_EXPIRE_TIME
            ];
            
        } catch (PDOException $e) {
            return ['success' => false, 'message' => 'Database error: ' . $e->getMessage()];
        }
    }
    
    public function logout($token = null) {
        try {
            if ($token) {
                // Rimuove il token specifico dal database
                $stmt = $this->db->prepare("DELETE FROM api_tokens WHERE token = :token");
                $stmt->bindParam(':token', $token);
                $stmt->execute();
            } else {
                // Se non è specificato un token, rimuove tutti i token dell'utente corrente
                if (isset($_SESSION['current_user'])) {
                    $stmt = $this->db->prepare("DELETE FROM api_tokens WHERE user_id = :user_id");
                    $stmt->bindParam(':user_id', $_SESSION['current_user']['id'], PDO::PARAM_INT);
                    $stmt->execute();
                }
            }
            
            // Pulisce la sessione
            unset($_SESSION['current_user']);
            
            return ['success' => true, 'message' => 'Logged out successfully'];
            
        } catch (PDOException $e) {
            return ['success' => false, 'message' => 'Logout error'];
        }
    }
    
    public function refreshToken($oldToken) {
        try {
            $payload = JWT::decode($oldToken, Config::JWT_SECRET);
            
            // Verifica se l'utente esiste ancora
            $stmt = $this->db->prepare("SELECT id, name, email FROM users WHERE id = :id");
            $stmt->bindParam(':id', $payload['user_id'], PDO::PARAM_INT);
            $stmt->execute();
            
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$user) {
                return ['success' => false, 'message' => 'User not found'];
            }
            
            // Genera un nuovo token
            $newPayload = [
                'user_id' => $user['id'],
                'email' => $user['email'],
                'iat' => time(),
                'exp' => time() + Config::JWT_EXPIRE_TIME
            ];
            
            $newToken = JWT::encode($newPayload, Config::JWT_SECRET);
            
            // Rimuove il vecchio token e inserisce il nuovo
            $stmt = $this->db->prepare("DELETE FROM api_tokens WHERE token = :old_token");
            $stmt->bindParam(':old_token', $oldToken);
            $stmt->execute();
            
            $stmt = $this->db->prepare("INSERT INTO api_tokens (user_id, token, expires_at) VALUES (:user_id, :token, :expires_at)");
            $stmt->bindParam(':user_id', $user['id'], PDO::PARAM_INT);
            $stmt->bindParam(':token', $newToken);
            $stmt->bindParam(':expires_at', date('Y-m-d H:i:s', time() + Config::JWT_EXPIRE_TIME));
            $stmt->execute();
            
            return [
                'success' => true,
                'token' => $newToken,
                'expires_in' => Config::JWT_EXPIRE_TIME
            ];
            
        } catch (Exception $e) {
            return ['success' => false, 'message' => 'Token refresh failed: ' . $e->getMessage()];
        }
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
    
    public function cleanExpiredTokens() {
        try {
            $stmt = $this->db->prepare("DELETE FROM api_tokens WHERE expires_at < NOW()");
            $stmt->execute();
            
            return ['success' => true, 'deleted' => $stmt->rowCount()];
            
        } catch (PDOException $e) {
            return ['success' => false, 'message' => 'Error cleaning expired tokens'];
        }
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
                
            case '/api/refresh':
                if ($method === 'POST') {
                    $this->refreshToken();
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
        $input = json_decode(file_get_contents('php://input'), true);
        $token = $input['token'] ?? null;
        
        $result = $this->auth->logout($token);
        $this->sendResponse($result);
    }
    
    private function refreshToken() {
        $input = json_decode(file_get_contents('php://input'), true);
        $token = $input['token'] ?? '';
        
        if (empty($token)) {
            $this->sendResponse(['error' => 'Token is required'], 400);
            return;
        }
        
        $result = $this->auth->refreshToken($token);
        $this->sendResponse($result, $result['success'] ? 200 : 401);
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