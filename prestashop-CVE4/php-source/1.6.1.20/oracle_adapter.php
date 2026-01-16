<?php
/**
 * Oracle adapter for PrestaShop 1.6.1.20 (FIXED)
 * 
 * This version includes HMAC validation which prevents padding oracle attacks.
 * Usage: php oracle_adapter.php <command> [args...]
 * 
 * Commands:
 *   encrypt <plaintext> <key> <iv>  - Encrypt plaintext and return cookie format
 *   check <ciphertext> <key> <iv>   - Check if HMAC and padding are valid
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
                
                // In 1.6.1.20, HMAC is checked first, preventing oracle
                $result = @$cipher->decrypt($ciphertext);
                
                // HMAC mismatch returns false without revealing padding
                $valid = ($result !== false);
                
                echo json_encode([
                    'status' => 'success',
                    'valid_padding' => $valid,
                    'note' => 'HMAC prevents padding oracle in this version'
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
