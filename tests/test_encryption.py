import os
import subprocess
import shutil
import sys

# Configuration
RUST_BIN = os.path.abspath("../lrzip-rust/target/debug/lrzip-rust")
C_BIN_PATH = "/home/cachy/Projects/Compression-tool/lrzip-next/src/lrzip-next"
TEST_DIR = "encryption_tests_tmp"
PASSWORD = "password123"

def ensure_dir(d):
    if os.path.exists(d):
        shutil.rmtree(d)
    os.makedirs(d)

def run_cmd(cmd, input=None, check=True):
    print(f"Executing: {' '.join(cmd)}")
    result = subprocess.run(cmd, input=input, capture_output=True, text=True)
    if check and result.returncode != 0:
        print(f"Command failed: {result.stderr}")
        print(f"STDOUT: {result.stdout}")
        return result
    return result

def test_rust_to_rust_enc(filename):
    print(f"\n--- Testing Rust -> Rust (Encrypted): {filename} ---")
    orig_path = os.path.join(TEST_DIR, filename)
    lrz_path = orig_path + ".lrz"
    out_path = orig_path + ".out"

    # Compress with Rust + Encryption
    # -e password
    res = run_cmd([RUST_BIN, orig_path, "-e", PASSWORD, "-o", lrz_path])
    if res.returncode != 0: return False

    # Decompress with Rust + Encryption
    res = run_cmd([RUST_BIN, "-d", lrz_path, "-e", PASSWORD, "-o", out_path])
    if res.returncode != 0: 
        print("Decompression failed!")
        return False

    # Check content
    with open(orig_path, 'rb') as f1, open(out_path, 'rb') as f2:
        if f1.read() != f2.read():
            print("Content mismatch!")
            return False
            
    print("SUCCESS")
    return True

def test_c_to_rust_enc(filename):
    print(f"\n--- Testing C -> Rust (Encrypted): {filename} ---")
    orig_path = os.path.join(TEST_DIR, filename)
    lrz_path = orig_path + ".c.lrz"
    out_path = orig_path + ".c.rust.out"

    # Compress with C + Encryption
    # lrzip -e -o output input (pw on stdin because --encrypt=pw is flaky in script)
    # Also double confirm password is required confirmation? Usually standard input works.
    res = run_cmd([C_BIN_PATH, "-e", "-o", lrz_path, orig_path], input=f"{PASSWORD}\n{PASSWORD}\n")
    if res.returncode != 0: return False

    # Decompress with Rust
    res = run_cmd([RUST_BIN, "-d", lrz_path, "-e", PASSWORD, "-o", out_path])
    if res.returncode != 0: 
        print("Decompression failed!")
        return False
        
    # Check content
    with open(orig_path, 'rb') as f1, open(out_path, 'rb') as f2:
        if f1.read() != f2.read():
            print("Content mismatch!")
            return False

    print("SUCCESS")
    return True

def main():
    ensure_dir(TEST_DIR)
    
    # Test file
    with open(os.path.join(TEST_DIR, "test.txt"), "w") as f:
        f.write("Encrypted content verification test." * 50)
        
    files = ["test.txt"]
    failed = 0
    
    for f in files:
        if not test_rust_to_rust_enc(f): failed += 1
        if not test_c_to_rust_enc(f): failed += 1
        
    if failed == 0:
        print("\nAll encryption tests passed!")
        sys.exit(0)
    else:
        print(f"\n{failed} encryption tests failed.")
        sys.exit(1)

if __name__ == "__main__":
    main()
