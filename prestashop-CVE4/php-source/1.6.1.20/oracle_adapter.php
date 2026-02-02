<?php
/**
 * Oracle adapter for PrestaShop 1.6.1.20 (FIXED)
 * 
 * Simple wrapper around PrestaShop's Rijndael encryption with HMAC.
 * Usage: php oracle_adapter.php <command> [args...]
 * 
 * Commands:
 *   encrypt <plaintext> <key> <iv>  - Encrypt plaintext and return cookie format
 *   decrypt <ciphertext> <key> <iv> - Decrypt ciphertext and return result
 */

require_once __DIR__ . '/Rijndael.php';

function main($argc, $argv) {
    if ($argc < 2) {
        fwrite(STDERR, "Usage: php oracle_adapter.php <command> [args...]\n");
        fwrite(STDERR, "Commands:\n");
        fwrite(STDERR, "  encrypt <plaintext> <key> <iv>\n");
        fwrite(STDERR, "  decrypt <ciphertext> <key> <iv>\n");
        exit(1);
    }

    $command = $argv[1];

    try {
        switch ($command) {
            case 'encrypt':
                if ($argc != 5) {
                    fwrite(STDERR, "Usage: encrypt <plaintext> <key> <iv>\n");
                    exit(1);
                }
                $plaintext = $argv[2];
                $key = $argv[3];
                $iv = $argv[4];
                
                $cipher = new RijndaelCore($key, $iv);
                $encrypted = $cipher->encrypt($plaintext);
                
                echo json_encode([
                    'status' => 'success',
                    'ciphertext' => $encrypted
                ]) . "\n";
                break;

            case 'decrypt':
                if ($argc != 5) {
                    fwrite(STDERR, "Usage: decrypt <ciphertext> <key> <iv>\n");
                    exit(1);
                }
                $ciphertext = $argv[2];
                $key = $argv[3];
                $iv = $argv[4];
                
                $cipher = new RijndaelCore($key, $iv);
                
                error_reporting(0);  // Suppress warnings
                $result = $cipher->decrypt($ciphertext);
                error_reporting(E_ALL);

                // Base64 encode the result to handle binary data safely
                if ($result === false || $result === null) {
                    $result_b64 = '';
                } else {
                    $result_b64 = base64_encode($result);
                }
                
                echo json_encode([
                    'status' => 'success',
                    'plaintext_b64' => $result_b64
                ]) . "\n";
                break;

            default:
                fwrite(STDERR, "Unknown command: $command\n");
                exit(1);
        }
    } catch (Exception $e) {
        echo json_encode([
            'status' => 'error',
            'message' => $e->getMessage()
        ]) . "\n";
        exit(1);
    }
}

main($argc, $argv);
