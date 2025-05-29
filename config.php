<?php
class Config {
    // Configurazione Database - AGGIORNATO per MiraDB
    const DB_HOST = 'localhost';
    const DB_NAME = 'MiraDB'; // Cambiato da 'api_database' a 'MiraDB'
    const DB_USER = 'root';
    const DB_PASS = '';
    const DB_CHARSET = 'utf8mb4';
    
    // Configurazione API
    const API_VERSION = '1.0';
    const API_TITLE = 'MiraDB Art API'; // Aggiornato il titolo
    const MAX_REQUESTS_PER_HOUR = 1000;
    
    // Configurazione JWT (se implementi l'autenticazione)
    const JWT_SECRET = 'your-secret-key-here-change-in-production';
    const JWT_EXPIRE_TIME = 3600; // 1 ora
    
    // Configurazione CORS
    const CORS_ORIGINS = ['*']; // In produzione, specifica i domini esatti
    const CORS_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'];
    const CORS_HEADERS = ['Content-Type', 'Authorization', 'X-Requested-With'];
    
    // Configurazione paginazione
    const DEFAULT_PAGE_SIZE = 10;
    const MAX_PAGE_SIZE = 100;
    
    // Configurazione logging
    const LOG_ERRORS = true;
    const LOG_FILE = 'logs/api_errors.log';
    
    // Configurazione cache
    const CACHE_ENABLED = false;
    const CACHE_TTL = 300; // 5 minuti
    
    // NUOVE CONFIGURAZIONI per MiraDB
    const SUPPORTED_LANGUAGES = ['it', 'en', 'es', 'fr']; // Lingue supportate per biografie/descrizioni
    const DEFAULT_LANGUAGE = 'it';
    const MAX_OPERE_PER_ARTIST = 100; // Limite massimo opere per artista
}

// Classe per la gestione degli errori
class ErrorHandler {
    public static function handleError($errno, $errstr, $errfile, $errline) {
        if (Config::LOG_ERRORS) {
            $message = date('Y-m-d H:i:s') . " - Error: [$errno] $errstr in $errfile on line $errline\n";
            error_log($message, 3, Config::LOG_FILE);
        }
        
        // Non mostrare errori PHP in produzione
        if (Config::LOG_ERRORS) {
            return true; // Non mostra l'errore
        }
        return false; // Mostra l'errore
    }
    
    public static function handleException($exception) {
        if (Config::LOG_ERRORS) {
            $message = date('Y-m-d H:i:s') . " - Exception: " . $exception->getMessage() . 
                      " in " . $exception->getFile() . " on line " . $exception->getLine() . "\n";
            error_log($message, 3, Config::LOG_FILE);
        }
        
        http_response_code(500);
        echo json_encode(['error' => 'Internal server error']);
        exit();
    }
}

// Impostazione degli handler di errore
set_error_handler(['ErrorHandler', 'handleError']);
set_exception_handler(['ErrorHandler', 'handleException']);

// Classe per la validazione - AGGIORNATA con validazioni specifiche per MiraDB
class Validator {
    public static function validateEmail($email) {
        return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
    }
    
    public static function validateRequired($data, $fields) {
        foreach ($fields as $field) {
            if (!isset($data[$field]) || empty(trim($data[$field]))) {
                return false;
            }
        }
        return true;
    }
    
    public static function sanitizeString($string) {
        return htmlspecialchars(trim($string), ENT_QUOTES, 'UTF-8');
    }
    
    public static function validateLength($string, $min = 0, $max = PHP_INT_MAX) {
        $length = strlen($string);
        return $length >= $min && $length <= $max;
    }
    
    // NUOVE VALIDAZIONI per MiraDB
    public static function validateLanguage($language) {
        return in_array($language, Config::SUPPORTED_LANGUAGES);
    }
    
    public static function validateCoordinates($lat, $lng) {
        return is_numeric($lat) && is_numeric($lng) && 
               $lat >= -90 && $lat <= 90 && 
               $lng >= -180 && $lng <= 180;
    }
    
    public static function validateDate($date, $format = 'Y-m-d') {
        $d = DateTime::createFromFormat($format, $date);
        return $d && $d->format($format) === $date;
    }
    
    public static function validateUrl($url) {
        return filter_var($url, FILTER_VALIDATE_URL) !== false;
    }
    
    public static function validateArtistName($nome, $cognome) {
        return !empty(trim($nome)) && !empty(trim($cognome)) && 
               strlen($nome) >= 2 && strlen($cognome) >= 2 &&
               strlen($nome) <= 50 && strlen($cognome) <= 50;
    }
    
    public static function validateOperaName($nomeOpera) {
        return !empty(trim($nomeOpera)) && 
               strlen($nomeOpera) >= 2 && 
               strlen($nomeOpera) <= 50;
    }
}

// Classe per le utilità - AGGIORNATA
class Utils {
    public static function generateToken($length = 32) {
        return bin2hex(random_bytes($length));
    }
    
    public static function hashPassword($password) {
        return password_hash($password, PASSWORD_DEFAULT);
    }
    
    public static function verifyPassword($password, $hash) {
        return password_verify($password, $hash);
    }
    
    public static function getCurrentTimestamp() {
        return date('Y-m-d H:i:s');
    }
    
    public static function formatResponse($status, $data = null, $message = null) {
        $response = ['status' => $status];
        
        if ($message !== null) {
            $response['message'] = $message;
        }
        
        if ($data !== null) {
            $response['data'] = $data;
        }
        
        $response['timestamp'] = self::getCurrentTimestamp();
        
        return $response;
    }
    
    // NUOVE UTILITÀ per MiraDB
    public static function formatArtistName($nome, $cognome) {
        return trim($cognome) . ', ' . trim($nome);
    }
    
    public static function sanitizeArtistParams($nome, $cognome) {
        return [
            'nome' => self::sanitizeString($nome),
            'cognome' => self::sanitizeString($cognome)
        ];
    }
    
    public static function sanitizeOperaName($nomeOpera) {
        return self::sanitizeString($nomeOpera);
    }
    
    public static function formatDateRange($dataNascita, $dataMorte = null) {
        $nascita = date('Y', strtotime($dataNascita));
        $morte = $dataMorte ? date('Y', strtotime($dataMorte)) : 'presente';
        return "($nascita - $morte)";
    }
    
    public static function buildImageUrl($baseUrl, $filename) {
        return rtrim($baseUrl, '/') . '/' . ltrim($filename, '/');
    }
    
    public static function filterEmptyValues($array) {
        return array_filter($array, function($value) {
            return !empty($value);
        });
    }
    
    private static function sanitizeString($string) {
        return htmlspecialchars(trim($string), ENT_QUOTES, 'UTF-8');
    }
}
?>