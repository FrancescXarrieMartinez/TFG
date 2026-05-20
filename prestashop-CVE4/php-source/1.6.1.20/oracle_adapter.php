<?php
/**
 * Oracle adapter for PrestaShop 1.6.1.20 (FIXED)
 *
 * Simple wrapper around PrestaShop's Rijndael encryption with HMAC.
 * Usage: php oracle_adapter.php <command> [args...]
 *
 * Commands:
 *   encrypt <plaintext> <key>  - Encrypt plaintext; IV is generated and prepended to ciphertext
 *   decrypt <ciphertext> <key> - Decrypt ciphertext; IV is extracted from ciphertext prefix
 */

require_once __DIR__ . '/Rijndael.php';

define('IV_SIZE', 16);

function main($argc, $argv) {
    if ($argc < 2) {
        fwrite(STDERR, "Usage: php oracle_adapter.php <command> [args...]\n");
        fwrite(STDERR, "Commands:\n");
        fwrite(STDERR, "  encrypt <plaintext> <key>\n");
        fwrite(STDERR, "  decrypt <ciphertext> <key>\n");
        exit(1);
    }

    $command = $argv[1];

    try {
        switch ($command) {
            case 'encrypt':
                if ($argc != 4) {
                    fwrite(STDERR, "Usage: encrypt <plaintext> <key>\n");
                    exit(1);
                }
                $plaintext = $argv[2];
                $key = $argv[3];

                // Generate a random IV and encrypt
                $iv_bytes = random_bytes(IV_SIZE);
                $cipher = new RijndaelCore($key, base64_encode($iv_bytes));
                $encrypted = $cipher->encrypt($plaintext);

                // encrypted = "hmac:base64(raw_ct)"
                // Prepend IV as a leading segment: "iv_b64:hmac:base64(raw_ct)"
                $packed = base64_encode($iv_bytes) . ':' . $encrypted;

                echo json_encode([
                    'status' => 'success',
                    'ciphertext' => $packed
                ]) . "\n";
                break;

            case 'decrypt':
                if ($argc != 4) {
                    fwrite(STDERR, "Usage: decrypt <ciphertext> <key>\n");
                    exit(1);
                }
                $ciphertext = $argv[2];
                $key = $argv[3];

                // Unpack: "iv_b64:hmac:base64(raw_ct)"
                $colon_pos = strpos($ciphertext, ':');
                if ($colon_pos === false) {
                    echo json_encode(['status' => 'success', 'plaintext_b64' => '']) . "\n";
                    break;
                }
                $iv_b64 = substr($ciphertext, 0, $colon_pos);
                $ct_for_rijndael = substr($ciphertext, $colon_pos + 1);  // "hmac:base64(raw_ct)"

                $cipher = new RijndaelCore($key, $iv_b64);

                error_reporting(0);  // Suppress warnings
                $result = $cipher->decrypt($ct_for_rijndael);
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
