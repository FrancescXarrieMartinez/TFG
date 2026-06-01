<?php
/**
 * Oracle adapter for PrestaShop 1.6.1.19 (VULNERABLE)
 *
 * Simple wrapper around PrestaShop's Rijndael encryption.
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
    fwrite(STDERR, "command=$command\n");

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

                // encrypted = base64(raw_ct) + 6-digit-length
                // Repack as base64(iv_bytes || raw_ct) + 6-digit-length
                $length_suffix = substr($encrypted, -6);
                $raw_ct = base64_decode(substr($encrypted, 0, -6));
                $packed = base64_encode($iv_bytes . $raw_ct) . $length_suffix;

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
                $start = microtime(true);

                // Unpack: base64(iv_bytes || raw_ct) + 6-digit-length
                $combined = base64_decode(substr($ciphertext, 0, -6));
                $iv_bytes = substr($combined, 0, IV_SIZE);
                $raw_ct = substr($combined, IV_SIZE);

                // Decrypt without automatic padding stripping (OPENSSL_ZERO_PADDING) so that
                // an all-padding block (\x10*16) is not silently collapsed to "" and mistaken
                // for a decryption failure.
                error_reporting(0);
                $raw_out = openssl_decrypt($raw_ct, 'AES-128-CBC', $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $iv_bytes);
                error_reporting(E_ALL);

                // Manual PKCS7 padding check
                $result_b64 = '';
                if ($raw_out !== false && strlen($raw_out) > 0) {
                    $pad_byte = ord($raw_out[strlen($raw_out) - 1]);
                    if ($pad_byte >= 1 && $pad_byte <= IV_SIZE) {
                        if (substr($raw_out, -$pad_byte) === str_repeat(chr($pad_byte), $pad_byte)) {
                            // Leak only one bit: fixed sentinel on VALID padding (no plaintext leak)
                            $result_b64 = base64_encode("\x01");
                        }
                    }
                }

                // One JSON line per decrypt call (reward telemetry), matching the other adapters' ORACLE_LOG format.
                $log_path = getenv('ORACLE_LOG');
                if ($log_path !== false && $log_path !== '') {
                    file_put_contents($log_path, sprintf("{\"valid\": %s, \"elapsed_ms\": %.3f}\n",
                        $result_b64 !== '' ? 'true' : 'false', (microtime(true) - $start) * 1000.0), FILE_APPEND);
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
