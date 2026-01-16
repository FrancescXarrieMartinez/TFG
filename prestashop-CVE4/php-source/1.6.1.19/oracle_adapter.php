<?php
/**
 * Oracle adapter for PrestaShop 1.6.1.19 (VULNERABLE)
 * 
 * This exposes the vulnerable Rijndael encryption as a padding oracle.
 * Usage: php oracle_adapter.php <command> [args...]
 * 
 * Commands:
 *   encrypt <plaintext> <key> <iv>  - Encrypt plaintext and return cookie format
 *   check <ciphertext> <key> <iv>   - Check if padding is valid (THE ORACLE)
 */

require_once __DIR__ . '/Rijndael.php';

function main($argc, $argv) {
    if ($argc < 2) {
        fwrite(STDERR, "Usage: php oracle_adapter.php <command> [args...]\n");
        fwrite(STDERR, "Commands:\n");
        fwrite(STDERR, "  encrypt <plaintext> <key> <iv>\n");
        fwrite(STDERR, "  check <ciphertext> <key> <iv>\n");
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

            case 'check':
                if ($argc != 5) {
                    fwrite(STDERR, "Usage: check <ciphertext> <key> <iv>\n");
                    exit(1);
                }
                $ciphertext = $argv[2];
                $key = $argv[3];
                $iv = $argv[4];
                
                $cipher = new RijndaelCore($key, $iv);
                
                // THE ORACLE: Try to decrypt and detect padding errors
                // We need to check the actual return value carefully
                error_reporting(0);  // Suppress warnings
                $result = $cipher->decrypt($ciphertext);
                error_reporting(E_ALL);
                
                // Valid padding: decrypt returns non-empty result
                // Invalid padding: openssl_decrypt returns false or empty string
                $valid = ($result !== false && $result !== null && $result !== '');
                
                echo json_encode([
                    'status' => 'success',
                    'valid_padding' => $valid
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
