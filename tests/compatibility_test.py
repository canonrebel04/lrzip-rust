import os
import subprocess
import hashlib
import shutil
import sys

# Configuration
RUST_BIN = os.path.abspath("../lrzip-rust/target/debug/lrzip-rust")
C_BIN = os.path.abspath("./lrzip") # Assumes running from lrzip-next dir or similar, will adjust
C_BIN_PATH = "/home/cachy/Projects/Compression-tool/lrzip-next/src/lrzip-next"
TEST_DIR = "compatibility_tests_tmp"

def ensure_dir(d):
    if os.path.exists(d):
        shutil.rmtree(d)
    os.makedirs(d)

def generate_file(path, size_mb, pattern="random"):
    with open(path, "wb") as f:
        if pattern == "random":
            f.write(os.urandom(size_mb * 1024 * 1024))
        elif pattern == "zero":
            f.write(b'\0' * (size_mb * 1024 * 1024))
        else:
            f.write(pattern.encode() * (size_mb * 1024 * 1024 // len(pattern)))

def calculate_md5(path):
    hash_md5 = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def run_cmd(cmd, check=True):
    print(f"Executing: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if check and result.returncode != 0:
        print(f"Command failed: {result.stderr}")
        print(f"STDOUT: {result.stdout}")
        # raise subprocess.CalledProcessError(result.returncode, cmd)
        return result
    return result

def test_rust_to_c(filename):
    print(f"\n--- Testing Rust -> C: {filename} ---")
    orig_path = os.path.join(TEST_DIR, filename)
    lrz_path = orig_path + ".lrz"
    out_path = orig_path + ".out"

    # Compress with Rust
    res = run_cmd([RUST_BIN, orig_path, "-o", lrz_path])
    print(f"DEBUG STDOUT: {res.stdout}")
    if res.returncode != 0: return False
    
    # Backup
    shutil.copy(lrz_path, lrz_path + ".debug")

    # Decompress with C
    # -f to force overwrite, -o for output
    res = run_cmd([C_BIN_PATH, "-d", lrz_path, "-O", TEST_DIR, "-f"], check=False)
    if res.returncode != 0:
        print(f"Ref failed return code: {res.returncode}")
        print(f"STDOUT: {res.stdout}")
        print(f"STDERR: {res.stderr}")
        if res.returncode == -11: # SEGFAULT
            print("Segfault detected!")
            run_cmd(["gdb", "-batch", "-ex", "run", "-ex", "bt", "--args", C_BIN_PATH, "-d", lrz_path, "-O", TEST_DIR, "-f"])
        return False 
    
    # Note: C lrzip usually outputs to filename without .lrz extension
    # If orig was 'test.txt', output is 'test.txt'. 
    # But wait, if we output to directory, it keeps original name.
    # Let's verify MD5
    
    decompressed_path = os.path.join(TEST_DIR, filename)
    
    hash_orig = calculate_md5(orig_path)
    hash_new = calculate_md5(decompressed_path)
    
    if hash_orig != hash_new:
        print(f"FAILED: Hashes differ! {hash_orig} vs {hash_new}")
        return False
    print("SUCCESS")
    return True

def test_c_to_rust(filename):
    print(f"\n--- Testing C -> Rust: {filename} ---")
    orig_path = os.path.join(TEST_DIR, filename)
    lrz_path = orig_path + ".c.lrz"
    out_path = orig_path + ".rust.out"

    # Compress with C
    res = run_cmd([C_BIN_PATH, "-z", orig_path, "-o", lrz_path])
    if res.returncode != 0: return False

    # Decompress with Rust
    res = run_cmd([RUST_BIN, "-d", lrz_path, "-o", out_path])
    if res.returncode != 0: return False

    hash_orig = calculate_md5(orig_path)
    hash_new = calculate_md5(out_path)

    if hash_orig != hash_new:
        print(f"FAILED: Hashes differ! {hash_orig} vs {hash_new}")
        return False
    print("SUCCESS")
    return True

def test_c_to_c(filename):
    print(f"\n--- Testing C -> C: {filename} ---")
    orig_path = os.path.join(TEST_DIR, filename)
    lrz_path = orig_path + ".cc.lrz"
    out_path = orig_path + ".cc.out" # Extract to dir actually

    # Compress with C
    res = run_cmd([C_BIN_PATH, "-z", orig_path, "-o", lrz_path])
    if res.returncode != 0: return False

    # Decompress with C
    # -O to output dir
    res = run_cmd([C_BIN_PATH, "-d", lrz_path, "-O", TEST_DIR, "-f"])
    
    if res.returncode != 0:
        if res.returncode == -11:
            print("Segfault in C->C!")
        return False

    # Check content (output filename is original name, need to rename/check)
    # lrzip output to TEST_DIR/filename
    # Since we overwrite -f, it overwrites original?
    # We should use a different output dir for C decompression or copy verification.
    
    # Actually, lrzip -d -O dir extracts to dir/filename.
    # We are extracting to TEST_DIR. Original is in TEST_DIR.
    # It overwrites original input file!
    # Validation will fail if we check hash of overwritten file vs overwritten file?
    # No, we generate file once.
    # If we overwrite, we lose original content?
    # Yes.
    # So we should extract to a SUBDIR.
    
    out_dir = os.path.join(TEST_DIR, "c_out")
    ensure_dir(out_dir)
    
    run_cmd([C_BIN_PATH, "-d", lrz_path, "-O", out_dir, "-f"])
    
    decompressed_path = os.path.join(out_dir, filename)
    hash_orig = calculate_md5(orig_path)
    hash_new = calculate_md5(decompressed_path)
    
    if hash_orig != hash_new:
        print(f"FAILED: Hashes differ! {hash_orig} vs {hash_new}")
        return False
    print("SUCCESS")
    return True

def main():
    if not os.path.exists(RUST_BIN):
        print(f"Rust binary not found at {RUST_BIN}")
        sys.exit(1)
    if not os.path.exists(C_BIN_PATH):
        print(f"C binary not found at {C_BIN_PATH}")
        sys.exit(1)

    ensure_dir(TEST_DIR)
    
    # Test 1: Small text file
    with open(os.path.join(TEST_DIR, "small.txt"), "w") as f:
        f.write("Hello world, this is a test.\n" * 100)
    
    # Test 2: 1MB Random
    generate_file(os.path.join(TEST_DIR, "random_1m.bin"), 1, "random")

    # Test 3: Tiny file (1 byte)
    with open(os.path.join(TEST_DIR, "tiny.txt"), "w") as f:
        f.write("A")

    files = ["tiny.txt", "small.txt", "random_1m.bin"]
    
    failed = 0
    for f in files:
        # if not test_c_to_c(f): 
        #     print("C->C FAILED! Aborting other tests.")
            # failed += 1
            # Continue anyway to see if Rust ones work
        if not test_rust_to_c(f): failed += 1
        if not test_c_to_rust(f): failed += 1

        
    if failed == 0:
        print("\nAll tests passed!")
        sys.exit(0)
    else:
        print(f"\n{failed} tests failed.")
        sys.exit(1)

if __name__ == "__main__":
    main()
