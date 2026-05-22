#!/usr/bin/env python3
"""
Quick test to verify both PrestaShop versions work correctly.
This doesn't run the attack, just verifies the oracle behavior.
"""

import subprocess
import sys
import os

def get_php_path():
    """Find PHP executable"""
    for cmd in ['/opt/homebrew/bin/php', 'php']:
        try:
            result = subprocess.run([cmd, '--version'], capture_output=True, text=True, timeout=2)
            if result.returncode == 0:
                return cmd
        except:
            continue
    raise FileNotFoundError("PHP not found")

def test_version(version, php_path):
    """Test oracle behavior for a specific version"""
    print(f"\n{'='*70}")
    print(f"Testing PrestaShop {version}")
    print('='*70)
    
    key = "MySecretKey12345"

    # Encrypt
    result = subprocess.run(
        [php_path, f"php-source/{version}/oracle_adapter.php", "encrypt", "Test123", key],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
    )
    
    if result.returncode != 0:
        print(f"❌ Encryption failed: {result.stderr}")
        return False
        
    import json
    data = json.loads(result.stdout)
    cookie = data['ciphertext']
    print(f"✓ Encrypted cookie: {cookie[:60]}...")
    
    # Test valid cookie
    result = subprocess.run(
        [php_path, f"php-source/{version}/oracle_adapter.php", "decrypt", cookie, key],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
    )
    data = json.loads(result.stdout)
    plaintext_b64 = data.get('plaintext_b64', '')

    # Apply the oracle logic from exploit
    # Empty plaintext_b64 means decrypt failed
    valid = bool(plaintext_b64)
    print(f"✓ Valid cookie check: {valid}")

    if not valid:
        print("❌ ERROR: Valid cookie should return true!")
        return False

    # Test corrupted cookie — flip a char in the actual ciphertext (position -7),
    # not the IV prefix, to ensure padding/HMAC failure
    corrupted = cookie[:-7] + ("A" if cookie[-7] != "A" else "B") + cookie[-6:]

    result = subprocess.run(
        [php_path, f"php-source/{version}/oracle_adapter.php", "decrypt", corrupted, key],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
    )
    data = json.loads(result.stdout)
    plaintext_b64_corrupted = data.get('plaintext_b64', '')
    
    # Apply the oracle logic from exploit
    valid_corrupted = bool(plaintext_b64_corrupted)
    print(f"✓ Corrupted cookie check: {valid_corrupted}")
    
    if valid_corrupted:
        print("❌ ERROR: Corrupted cookie should return false!")
        return False
    
    return True

if __name__ == "__main__":
    # Change to prestashop-CVE4 directory
    if not os.path.exists("php-source"):
        if os.path.exists("prestashop-CVE4/php-source"):
            os.chdir("prestashop-CVE4")
        else:
            print("Error: Run from project root or prestashop-CVE4 directory", file=sys.stderr)
            sys.exit(1)
    
    try:
        php_path = get_php_path()
        print(f"Using PHP: {php_path}")
        
        success_19 = test_version("1.6.1.19", php_path)
        success_20 = test_version("1.6.1.20", php_path)
        
        print(f"\n{'='*70}")
        print("SUMMARY")
        print('='*70)
        print(f"PrestaShop 1.6.1.19 (vulnerable): {'✓ PASSED' if success_19 else '❌ FAILED'}")
        print(f"PrestaShop 1.6.1.20 (fixed):      {'✓ PASSED' if success_20 else '❌ FAILED'}")
        
        if success_19 and success_20:
            print("\n✓ Both versions working correctly!")
            sys.exit(0)
        else:
            print("\n❌ Some tests failed")
            sys.exit(1)
            
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)
