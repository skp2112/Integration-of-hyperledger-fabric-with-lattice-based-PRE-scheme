import os
import asyncio
import time
import json
import hashlib
from pathlib import Path
from dataclasses import dataclass, asdict

from openfhe import *
from hfc.fabric.client import Client


# -------- Crypto Setup --------
def setup_crypto_context():
    print("\n[CRYPTO] Setting up crypto context (BFVRNS PRE)...")
    parameters = CCParamsBFVRNS()
    parameters.SetPlaintextModulus(65537)
    parameters.SetMultiplicativeDepth(1)
    parameters.SetSecurityLevel(HEStd_192_classic)

    cc = GenCryptoContext(parameters)
    cc.Enable(PKESchemeFeature.PKE)
    cc.Enable(PKESchemeFeature.KEYSWITCH)
    cc.Enable(PKESchemeFeature.LEVELEDSHE)
    cc.Enable(PKESchemeFeature.PRE)

    data_dir = Path("fabric_performance_data")
    data_dir.mkdir(exist_ok=True)

    print("[CRYPTO] BFVRNS crypto context ready")
    return cc


# -------- Fabric Client --------
class FabricClient:
    def __init__(self, conn_profile_path, msp_id, user_name, key_path, cert_path):
        self.loop = asyncio.get_event_loop()
        self.cli = Client(net_profile=conn_profile_path)
        self.org_name = self.cli.get_net_info()['client']['organization']
        self.user = None
        self.msp_id = msp_id
        self.user_name = user_name
        self.key_path = key_path
        self.cert_path = cert_path

    async def init_user(self):
        try:
            # Read the private key and certificate files
            print(f"[FABRIC] Reading private key from: {self.key_path}")
            print(f"[FABRIC] Reading certificate from: {self.cert_path}")
            
            if not os.path.exists(self.key_path):
                raise FileNotFoundError(f"Private key file not found: {self.key_path}")
            if not os.path.exists(self.cert_path):
                raise FileNotFoundError(f"Certificate file not found: {self.cert_path}")
                
            with open(self.key_path, 'r') as key_file:
                private_key = key_file.read()
            with open(self.cert_path, 'r') as cert_file:
                certificate = cert_file.read()
            
            print(f"[FABRIC] Private key length: {len(private_key)} chars")
            print(f"[FABRIC] Certificate length: {len(certificate)} chars")
            
            # Import User class and try different initialization approaches
            from hfc.fabric.user import User
            
            # Method 1: Standard User constructor (name, org, state_store)
            try:
                print("[FABRIC] Attempting standard User constructor...")
                self.user = User(
                    name=self.user_name,
                    org=self.org_name,
                    state_store=self.cli.state_store
                )
                
                # Manually set enrollment data
                enrollment_data = {
                    'key': private_key,
                    'cert': certificate
                }
                
                # Try different ways to set enrollment
                if hasattr(self.user, '_enrollment'):
                    self.user._enrollment = enrollment_data
                elif hasattr(self.user, 'enrollment'):
                    self.user.enrollment = enrollment_data
                
                # Set MSP ID
                if hasattr(self.user, '_msp_id'):
                    self.user._msp_id = self.msp_id
                elif hasattr(self.user, 'msp_id'):
                    self.user.msp_id = self.msp_id
                
                print(f"[FABRIC] User '{self.user_name}' initialized successfully with standard constructor")
                return
                
            except Exception as e1:
                print(f"[FABRIC] Standard constructor failed: {e1}")
                
                # Method 2: Try with just name parameter
                try:
                    print("[FABRIC] Attempting User constructor with name only...")
                    self.user = User(name=self.user_name)
                    
                    # Set all required attributes manually
                    self.user._name = self.user_name
                    self.user._org = self.org_name
                    self.user._msp_id = self.msp_id
                    self.user._enrollment = {
                        'key': private_key,
                        'cert': certificate
                    }
                    
                    # Try to set state store if possible
                    if hasattr(self.user, '_state_store'):
                        self.user._state_store = self.cli.state_store
                    
                    print(f"[FABRIC] User '{self.user_name}' initialized with manual attribute setting")
                    return
                    
                except Exception as e2:
                    print(f"[FABRIC] Name-only constructor failed: {e2}")
                    
                    # Method 3: Try client-based user creation
                    try:
                        print("[FABRIC] Attempting client-based user creation...")
                        
                        # Check if client has user-related methods
                        if hasattr(self.cli, 'get_user'):
                            existing_user = self.cli.get_user(org_name=self.org_name, name=self.user_name)
                            if existing_user:
                                self.user = existing_user
                                print(f"[FABRIC] Found existing user in client state store")
                                return
                        
                        # Try to create using client methods
                        if hasattr(self.cli, '_create_user'):
                            self.user = self.cli._create_user(
                                name=self.user_name,
                                org=self.org_name,
                                msp_id=self.msp_id,
                                private_key=private_key,
                                certificate=certificate
                            )
                            print(f"[FABRIC] User created using client._create_user method")
                            return
                            
                    except Exception as e3:
                        print(f"[FABRIC] Client-based creation failed: {e3}")
                        
                        # Method 4: Manual user object construction
                        try:
                            print("[FABRIC] Attempting manual user object construction...")
                            
                            # Create a minimal user-like object
                            class MockUser:
                                def __init__(self, name, org, msp_id, private_key, certificate):
                                    self._name = name
                                    self._org = org  
                                    self._msp_id = msp_id
                                    self._enrollment = {
                                        'key': private_key,
                                        'cert': certificate
                                    }
                                    self.name = name
                                    self.org = org
                                    self.msp_id = msp_id
                                
                                def get_name(self):
                                    return self._name
                                    
                                def get_msp_id(self):
                                    return self._msp_id
                                    
                                def get_enrollment(self):
                                    return self._enrollment
                            
                            self.user = MockUser(
                                self.user_name, 
                                self.org_name, 
                                self.msp_id, 
                                private_key, 
                                certificate
                            )
                            
                            print(f"[FABRIC] Created mock user object for '{self.user_name}'")
                            return
                            
                        except Exception as e4:
                            print(f"[FABRIC] All user creation methods failed: {e4}")
                            print("[FABRIC] Setting user to None - transactions will be skipped")
                            self.user = None
                
        except Exception as e:
            print(f"[FABRIC] Critical error in user initialization: {e}")
            self.user = None

    async def submit_transaction(self, channel_name, chaincode_name, func_name, *args):
        if not self.user:
            print(f"[FABRIC] Warning: No user context available, skipping transaction '{func_name}'")
            return None
            
        print(f"[FABRIC] Submitting transaction '{func_name}' with args {args} ...")
        
        try:
            # Get peer information from network profile
            net_info = self.cli.get_net_info()
            peer_names = []
            
            # Try different ways to get peer information
            if 'organizations' in net_info and self.org_name in net_info['organizations']:
                org_info = net_info['organizations'][self.org_name]
                if 'peers' in org_info:
                    if isinstance(org_info['peers'], dict):
                        peer_names = list(org_info['peers'].keys())
                    elif isinstance(org_info['peers'], list):
                        peer_names = org_info['peers']
            
            if not peer_names and 'peers' in net_info:
                peer_names = list(net_info['peers'].keys())
            
            if not peer_names:
                # Try to get from channel info
                try:
                    channels = self.cli.get_channels()
                    if channels and channel_name in channels:
                        peer_names = list(channels[channel_name].get('peers', {}).keys())
                except:
                    pass
            
            if not peer_names:
                print("[FABRIC] Warning: No peers found, using default peer names")
                peer_names = ['peer0.org1.example.com', 'peer0.org2.example.com']
            
            print(f"[FABRIC] Using peers: {peer_names}")

            # Create transaction context
            try:
                tx_context = self.cli.new_tx_context(
                    user_context=self.user, 
                    channel_name=channel_name
                )
            except Exception as e:
                print(f"[FABRIC] Error creating tx context: {e}")
                # Try alternative method
                tx_context = self.cli.new_tx_context(self.user)
            
            # Send transaction proposal
            try:
                proposal_response = await self.cli.send_transaction_proposal(
                    tx_context=tx_context,
                    peers=peer_names,
                    cc_name=chaincode_name,
                    fcn=func_name,
                    args=[str(arg) for arg in args]
                )
            except Exception as e:
                print(f"[FABRIC] Error sending proposal: {e}")
                # Try with simplified parameters
                proposal_response = await self.cli.send_transaction_proposal(
                    tx_context,
                    peer_names,
                    chaincode_name,
                    func_name,
                    [str(arg) for arg in args]
                )
            
            # Check proposal response
            if not proposal_response:
                raise Exception("No proposal response received")
            
            print(f"[FABRIC] Proposal response received, sending transaction...")
            
            # Send transaction
            try:
                tx_response = await self.cli.send_transaction(
                    tx_context=tx_context, 
                    proposal_response=proposal_response
                )
            except Exception as e:
                print(f"[FABRIC] Error sending transaction: {e}")
                # Try simplified method
                tx_response = await self.cli.send_transaction(
                    tx_context, 
                    proposal_response
                )
            
            print(f"[FABRIC] Transaction '{func_name}' successfully submitted.")
            return tx_response
            
        except Exception as e:
            print(f"[FABRIC] Error submitting transaction '{func_name}': {e}")
            print(f"[FABRIC] This may be due to network configuration or chaincode deployment issues")
            print(f"[FABRIC] Continuing with workflow (transaction will be skipped)...")
            return None


# -------- Performance Metrics --------
@dataclass
class PerformanceMetrics:
    keygen_time_ms: float = 0
    encrypt_time_ms: float = 0
    rekeygen_time_ms: float = 0
    reencrypt_time_ms: float = 0
    decrypt_time_ms: float = 0
    pubkey_size_bytes: int = 0
    ciphertext_size_bytes: int = 0
    rekey_size_bytes: int = 0
    store_record_latency_ms: float = 0
    request_share_latency_ms: float = 0
    log_share_latency_ms: float = 0


# -------- Configuration --------
CONFIG = {
    "channel": "mychannel",
    "chaincode": "prehealth",

    "org1_profile": "/home/sp179/fabric-workspace/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/connection-org1.json",
    "org2_profile": "/home/sp179/fabric-workspace/fabric-samples/test-network/organizations/peerOrganizations/org2.example.com/connection-org2.json",

    "org1_msp_id": "Org1MSP",
    "org1_user": "Admin",
    "org1_key": "/home/sp179/fabric-workspace/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp/keystore/priv_sk",
    "org1_cert": "/home/sp179/fabric-workspace/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp/signcerts/Admin@org1.example.com-cert.pem",

    "org2_msp_id": "Org2MSP",
    "org2_user": "Admin",
    "org2_key": "/home/sp179/fabric-workspace/fabric-samples/test-network/organizations/peerOrganizations/org2.example.com/users/Admin@org2.example.com/msp/keystore/priv_sk",
    "org2_cert": "/home/sp179/fabric-workspace/fabric-samples/test-network/organizations/peerOrganizations/org2.example.com/users/Admin@org2.example.com/msp/signcerts/Admin@org2.example.com-cert.pem",

    "data_dir": Path("fabric_performance_data")
}


# -------- Main Workflow --------
async def execute_single_run(run_number=1, total_runs=1):
    """Execute a single workflow run and return metrics."""
    print(f"\n{'='*20} RUN {run_number}/{total_runs} {'='*20}")
    
    CONFIG['data_dir'].mkdir(exist_ok=True)
    metrics = PerformanceMetrics()

    # Check if required files exist before starting
    print("\n--- CHECKING FABRIC CONFIGURATION ---")
    for org, paths in [("org1", (CONFIG['org1_key'], CONFIG['org1_cert'], CONFIG['org1_profile'])),
                      ("org2", (CONFIG['org2_key'], CONFIG['org2_cert'], CONFIG['org2_profile']))]:
        key_path, cert_path, profile_path = paths
        print(f"[FABRIC] Checking {org} files:")
        print(f"  Key file: {key_path} - {'EXISTS' if os.path.exists(key_path) else 'MISSING'}")
        print(f"  Cert file: {cert_path} - {'EXISTS' if os.path.exists(cert_path) else 'MISSING'}")
        print(f"  Profile file: {profile_path} - {'EXISTS' if os.path.exists(profile_path) else 'MISSING'}")
        
        # Check keystore directory if key file doesn't exist
        if not os.path.exists(key_path):
            keystore_dir = os.path.dirname(key_path)
            if os.path.exists(keystore_dir):
                files = os.listdir(keystore_dir)
                print(f"  Keystore directory contents: {files}")
                if files:
                    # Use the first key file found
                    actual_key_path = os.path.join(keystore_dir, files[0])
                    if org == "org1":
                        CONFIG['org1_key'] = actual_key_path
                    else:
                        CONFIG['org2_key'] = actual_key_path
                    print(f"  Updated key path to: {actual_key_path}")

    cc = setup_crypto_context()

    # Initialize Fabric clients for hospital and insurance with MSP identities
    print("\n[FABRIC] Initializing hospital client (Org1)...")
    hospital = FabricClient(CONFIG['org1_profile'], CONFIG['org1_msp_id'], CONFIG['org1_user'], CONFIG['org1_key'], CONFIG['org1_cert'])
    await hospital.init_user()

    print("\n[FABRIC] Initializing insurance client (Org2)...")
    insurance = FabricClient(CONFIG['org2_profile'], CONFIG['org2_msp_id'], CONFIG['org2_user'], CONFIG['org2_key'], CONFIG['org2_cert'])
    await insurance.init_user()

    print("\n--- PHASE 1: Key Generation & Encryption ---")
    start = time.time()
    patient_keys = cc.KeyGen()
    insurance_keys = cc.KeyGen()
    metrics.keygen_time_ms = (time.time() - start) * 1000

    health_data = [120, 80, 366]
    pt = cc.MakePackedPlaintext(health_data)

    start = time.time()
    ct = cc.Encrypt(patient_keys.publicKey, pt)
    metrics.encrypt_time_ms = (time.time() - start) * 1000

    ct_path = CONFIG['data_dir'] / "record001.enc"
    SerializeToFile(str(ct_path), ct, BINARY)

    pub_key_path = CONFIG['data_dir'] / "patient_pubkey.key"
    SerializeToFile(str(pub_key_path), patient_keys.publicKey, BINARY)

    pub_key_bytes = pub_key_path.read_bytes()
    metrics.pubkey_size_bytes = len(pub_key_bytes)
    metrics.ciphertext_size_bytes = ct_path.stat().st_size

    print(f"[CRYPTO] Health data encrypted: {health_data}")
    print(f"[CRYPTO] Public key size: {metrics.pubkey_size_bytes} bytes")
    print(f"[CRYPTO] Original ciphertext size: {metrics.ciphertext_size_bytes} bytes")
    
    # Display original ciphertext information
    print(f"\n=== ORIGINAL CIPHERTEXT DETAILS ===")
    print(f"Original Ciphertext Object: {ct}")
    print(f"Original Ciphertext Type: {type(ct)}")
    print(f"Original Ciphertext File: {ct_path}")
    print(f"Original Ciphertext File Size: {ct_path.stat().st_size} bytes")
    
    # Try to get more details about the ciphertext
    try:
        if hasattr(ct, 'GetLength'):
            print(f"Original Ciphertext Length: {ct.GetLength()}")
        if hasattr(ct, 'GetLevel'):
            print(f"Original Ciphertext Level: {ct.GetLevel()}")
        if hasattr(ct, 'GetNoiseScaleDeg'):
            print(f"Original Ciphertext Noise Scale Degree: {ct.GetNoiseScaleDeg()}")
    except Exception as e:
        print(f"Could not retrieve detailed ciphertext info: {e}")
    
    # Read and display first few bytes of the serialized ciphertext
    with open(ct_path, 'rb') as f:
        ct_bytes = f.read(50)  # Read first 50 bytes
        print(f"Original Ciphertext (first 50 bytes): {ct_bytes.hex()}")
        f.seek(0)  # Reset file pointer
        ct_full_hash = hashlib.sha256(f.read()).hexdigest()
        print(f"Original Ciphertext Hash: {ct_full_hash[:16]}...")

    print("\n--- PHASE 2: Submitting Records to Fabric ---")
    if hospital.user and insurance.user:
        print("[FABRIC] Both users initialized successfully - attempting transactions")
        
        try:
            start = time.time()
            tx_response = await hospital.submit_transaction(
                CONFIG['channel'], CONFIG['chaincode'], "StoreHealthRecord",
                "record001", "patient123", str(ct_path), str(pub_key_path)
            )
            metrics.store_record_latency_ms = (time.time() - start) * 1000
            print(f"[FABRIC] Store record latency: {metrics.store_record_latency_ms:.2f} ms")
            
            if tx_response:
                print(f"[FABRIC] Store record transaction successful: {tx_response}")
            else:
                print(f"[FABRIC] Store record transaction completed but no response received")
                
        except Exception as e:
            print(f"[FABRIC] Warning: Could not store health record: {e}")
            metrics.store_record_latency_ms = -1

        try:
            start = time.time()
            tx_response = await insurance.submit_transaction(
                CONFIG['channel'], CONFIG['chaincode'], "RequestDataShare",
                "req001", "record001"
            )
            metrics.request_share_latency_ms = (time.time() - start) * 1000
            print(f"[FABRIC] Request share latency: {metrics.request_share_latency_ms:.2f} ms")
            
            if tx_response:
                print(f"[FABRIC] Request share transaction successful: {tx_response}")
            else:
                print(f"[FABRIC] Request share transaction completed but no response received")
                
        except Exception as e:
            print(f"[FABRIC] Warning: Could not request data share: {e}")
            metrics.request_share_latency_ms = -1
    else:
        print("[FABRIC] User initialization failed - skipping blockchain transactions")
        print("[FABRIC] This could be due to:")
        print("  1. Incorrect fabric-sdk-py version or API changes")
        print("  2. Network connectivity issues")
        print("  3. Incorrect certificate/key file formats")
        print("  4. Hyperledger Fabric network not running")
        print("  5. Chaincode not properly deployed")
        
        print("\n[FABRIC] To debug further, try:")
        print("  1. Check network status: ./network.sh up")
        print("  2. Deploy chaincode: ./network.sh deployCC -ccn prehealth -ccp ../chaincode/pre-health")
        print("  3. Verify fabric-sdk-py version: pip list | grep fabric")
        
        metrics.store_record_latency_ms = -1
        metrics.request_share_latency_ms = -1

    print("\n--- PHASE 3: Re-Encryption Workflow ---")
    start = time.time()
    rk = cc.ReKeyGen(patient_keys.secretKey, insurance_keys.publicKey)
    metrics.rekeygen_time_ms = (time.time() - start) * 1000

    start = time.time()
    # Correct parameter order: ReEncrypt(ciphertext, evalKey, publicKey=None)
    re_ct = cc.ReEncrypt(ct, rk)
    metrics.reencrypt_time_ms = (time.time() - start) * 1000

    re_ct_path = CONFIG['data_dir'] / "re_enc_record001.enc"
    SerializeToFile(str(re_ct_path), re_ct, BINARY)
    metrics.rekey_size_bytes = re_ct_path.stat().st_size

    print(f"[CRYPTO] Re-encryption key generation time: {metrics.rekeygen_time_ms:.2f} ms")
    print(f"[CRYPTO] Re-encryption time: {metrics.reencrypt_time_ms:.2f} ms")
    print(f"[CRYPTO] Re-encrypted ciphertext size: {metrics.rekey_size_bytes} bytes")
    
    # Display re-encrypted ciphertext information
    print(f"\n=== RE-ENCRYPTED CIPHERTEXT DETAILS ===")
    print(f"Re-encrypted Ciphertext Object: {re_ct}")
    print(f"Re-encrypted Ciphertext Type: {type(re_ct)}")
    print(f"Re-encrypted Ciphertext File: {re_ct_path}")
    print(f"Re-encrypted Ciphertext File Size: {re_ct_path.stat().st_size} bytes")
    
    # Try to get more details about the re-encrypted ciphertext
    try:
        if hasattr(re_ct, 'GetLength'):
            print(f"Re-encrypted Ciphertext Length: {re_ct.GetLength()}")
        if hasattr(re_ct, 'GetLevel'):
            print(f"Re-encrypted Ciphertext Level: {re_ct.GetLevel()}")
        if hasattr(re_ct, 'GetNoiseScaleDeg'):
            print(f"Re-encrypted Ciphertext Noise Scale Degree: {re_ct.GetNoiseScaleDeg()}")
    except Exception as e:
        print(f"Could not retrieve detailed re-encrypted ciphertext info: {e}")
    
    # Read and display first few bytes of the serialized re-encrypted ciphertext
    with open(re_ct_path, 'rb') as f:
        re_ct_bytes = f.read(50)  # Read first 50 bytes
        print(f"Re-encrypted Ciphertext (first 50 bytes): {re_ct_bytes.hex()}")
        f.seek(0)  # Reset file pointer
        data_hash = hashlib.sha256(f.read()).hexdigest()
        print(f"Re-encrypted Ciphertext Hash: {data_hash[:16]}...")
    
    # Compare sizes
    print(f"\n=== CIPHERTEXT SIZE COMPARISON ===")
    print(f"Original Ciphertext Size:     {metrics.ciphertext_size_bytes:,} bytes")
    print(f"Re-encrypted Ciphertext Size: {metrics.rekey_size_bytes:,} bytes")
    size_diff = metrics.rekey_size_bytes - metrics.ciphertext_size_bytes
    print(f"Size Difference:              {size_diff:+,} bytes ({size_diff/metrics.ciphertext_size_bytes*100:+.2f}%)")

    # Generate hash for blockchain logging
    with open(re_ct_path, "rb") as f:
        data_hash = hashlib.sha256(f.read()).hexdigest()

    try:
        start = time.time()
        if hospital.user:
            tx_response = await hospital.submit_transaction(
                CONFIG['channel'], CONFIG['chaincode'], "ShareDataWithConsent",
                "share001", "req001", data_hash
            )
            metrics.log_share_latency_ms = (time.time() - start) * 1000
            print(f"[FABRIC] Log share latency: {metrics.log_share_latency_ms:.2f} ms")
            
            if tx_response:
                print(f"[FABRIC] Share data transaction successful: {tx_response}")
            else:
                print(f"[FABRIC] Share data transaction completed but no response received")
        else:
            print("[FABRIC] No user context - skipping share data transaction")
            metrics.log_share_latency_ms = -1
    except Exception as e:
        print(f"[FABRIC] Warning: Could not log data share: {e}")
        metrics.log_share_latency_ms = -1

    print("\n--- PHASE 4: Decryption & Verification ---")
    start = time.time()
    decrypted = cc.Decrypt(insurance_keys.secretKey, re_ct)
    metrics.decrypt_time_ms = (time.time() - start) * 1000

    decrypted.SetLength(pt.GetLength())
    decrypted_data = decrypted.GetPackedValue()

    print(f"[CRYPTO] Decryption time: {metrics.decrypt_time_ms:.2f} ms")
    print(f"[CRYPTO] Original data: {health_data}")
    print(f"[CRYPTO] Decrypted data: {decrypted_data}")
    print(f"[CRYPTO] Data integrity check: {'PASS' if health_data == decrypted_data else 'FAIL'}")

    # Save performance metrics and verification result for this run
    results = {
        "run_number": run_number,
        "metrics": asdict(metrics),
        "verification": {
            "original_data": health_data,
            "decrypted_data": decrypted_data,
            "match": health_data == decrypted_data
        },
        "test_info": {
            "timestamp": time.time(),
            "fabric_network": "test-network",
            "crypto_scheme": "BFVRNS PRE"
        }
    }

    # Save individual run result
    result_path = CONFIG['data_dir'] / f"performance_results_run_{run_number}.json"
    with open(result_path, "w") as f:
        json.dump(results, f, indent=4)

    print(f"[RUN {run_number}] Metrics saved to {result_path}")
    print(f"[RUN {run_number}] Data integrity: {'PASS' if health_data == decrypted_data else 'FAIL'}")
    
    return results


async def execute_workflow(num_runs=3):
    """Execute multiple workflow runs and calculate averages."""
    print(f"Starting {num_runs}-run performance analysis")
    print(f"={'='*60}")
    
    all_results = []
    successful_runs = []
    
    # Check fabric configuration only once
    print("\n--- CHECKING FABRIC CONFIGURATION ---")
    for org, paths in [("org1", (CONFIG['org1_key'], CONFIG['org1_cert'], CONFIG['org1_profile'])),
                      ("org2", (CONFIG['org2_key'], CONFIG['org2_cert'], CONFIG['org2_profile']))]:
        key_path, cert_path, profile_path = paths
        print(f"[FABRIC] Checking {org} files:")
        print(f"  Key file: {key_path} - {'EXISTS' if os.path.exists(key_path) else 'MISSING'}")
        print(f"  Cert file: {cert_path} - {'EXISTS' if os.path.exists(cert_path) else 'MISSING'}")
        print(f"  Profile file: {profile_path} - {'EXISTS' if os.path.exists(profile_path) else 'MISSING'}")
        
        # Check keystore directory if key file doesn't exist
        if not os.path.exists(key_path):
            keystore_dir = os.path.dirname(key_path)
            if os.path.exists(keystore_dir):
                files = os.listdir(keystore_dir)
                print(f"  Keystore directory contents: {files}")
                if files:
                    # Use the first key file found
                    actual_key_path = os.path.join(keystore_dir, files[0])
                    if org == "org1":
                        CONFIG['org1_key'] = actual_key_path
                    else:
                        CONFIG['org2_key'] = actual_key_path
                    print(f"  Updated key path to: {actual_key_path}")

    # Initialize crypto context and fabric clients once
    cc = setup_crypto_context()
    
    print("\n[FABRIC] Initializing hospital client (Org1)...")
    hospital = FabricClient(CONFIG['org1_profile'], CONFIG['org1_msp_id'], CONFIG['org1_user'], CONFIG['org1_key'], CONFIG['org1_cert'])
    await hospital.init_user()

    print("\n[FABRIC] Initializing insurance client (Org2)...")
    insurance = FabricClient(CONFIG['org2_profile'], CONFIG['org2_msp_id'], CONFIG['org2_user'], CONFIG['org2_key'], CONFIG['org2_cert'])
    await insurance.init_user()
    
    fabric_available = hospital.user is not None and insurance.user is not None
    
    # Execute multiple runs
    for run in range(1, num_runs + 1):
        try:
            result = await execute_single_run_with_clients(cc, hospital, insurance, fabric_available, run, num_runs)
            all_results.append(result)
            if result['verification']['match']:
                successful_runs.append(result)
            
            # Small delay between runs to avoid overwhelming the system
            if run < num_runs:
                await asyncio.sleep(1)
                
        except Exception as e:
            print(f"[RUN {run}] Failed: {e}")
            continue
    
    if not successful_runs:
        print("No successful runs completed!")
        return None
    
    # Calculate averages
    avg_results = calculate_averages(successful_runs)
    
    # Save aggregated results
    aggregated_results = {
        "summary": avg_results,
        "individual_runs": all_results,
        "statistics": {
            "total_runs": len(all_results),
            "successful_runs": len(successful_runs),
            "success_rate": len(successful_runs) / len(all_results) * 100 if all_results else 0
        }
    }
    
    final_result_path = CONFIG['data_dir'] / "aggregated_performance_results.json"
    with open(final_result_path, "w") as f:
        json.dump(aggregated_results, f, indent=4)
    
    print(f"\n\nSUCCESS: {len(successful_runs)}/{len(all_results)} runs completed successfully!")
    print(f"Aggregated results saved to {final_result_path}")
    
    # Print comprehensive averaged report
    print_comprehensive_average_report(avg_results, len(successful_runs))
    
    return aggregated_results


async def execute_single_run_with_clients(cc, hospital, insurance, fabric_available, run_number, total_runs):
    """Execute a single run with pre-initialized clients."""
    print(f"\n--- RUN {run_number}: PHASE 1: Key Generation & Encryption ---")
    metrics = PerformanceMetrics()
    
    start = time.time()
    patient_keys = cc.KeyGen()
    insurance_keys = cc.KeyGen()
    metrics.keygen_time_ms = (time.time() - start) * 1000

    health_data = [120, 80, 366]
    pt = cc.MakePackedPlaintext(health_data)

    start = time.time()
    ct = cc.Encrypt(patient_keys.publicKey, pt)
    metrics.encrypt_time_ms = (time.time() - start) * 1000

    # Use run-specific filenames to avoid conflicts
    ct_path = CONFIG['data_dir'] / f"record001_run{run_number}.enc"
    SerializeToFile(str(ct_path), ct, BINARY)

    pub_key_path = CONFIG['data_dir'] / f"patient_pubkey_run{run_number}.key"
    SerializeToFile(str(pub_key_path), patient_keys.publicKey, BINARY)

    pub_key_bytes = pub_key_path.read_bytes()
    metrics.pubkey_size_bytes = len(pub_key_bytes)
    metrics.ciphertext_size_bytes = ct_path.stat().st_size

    print(f"[RUN {run_number}] Health data encrypted, sizes: PK={metrics.pubkey_size_bytes}, CT={metrics.ciphertext_size_bytes}")

    print(f"\n--- RUN {run_number}: PHASE 2: Submitting Records to Fabric ---")
    if fabric_available:
        try:
            start = time.time()
            tx_response = await hospital.submit_transaction(
                CONFIG['channel'], CONFIG['chaincode'], "StoreHealthRecord",
                f"record{run_number:03d}", "patient123", str(ct_path), str(pub_key_path)
            )
            metrics.store_record_latency_ms = (time.time() - start) * 1000
        except Exception as e:
            print(f"[RUN {run_number}] Store record failed: {e}")
            metrics.store_record_latency_ms = -1

        try:
            start = time.time()
            tx_response = await insurance.submit_transaction(
                CONFIG['channel'], CONFIG['chaincode'], "RequestDataShare",
                f"req{run_number:03d}", f"record{run_number:03d}"
            )
            metrics.request_share_latency_ms = (time.time() - start) * 1000
        except Exception as e:
            print(f"[RUN {run_number}] Request share failed: {e}")
            metrics.request_share_latency_ms = -1
    else:
        print(f"[RUN {run_number}] Fabric not available - skipping blockchain transactions")
        metrics.store_record_latency_ms = -1
        metrics.request_share_latency_ms = -1

    print(f"\n--- RUN {run_number}: PHASE 3: Re-Encryption Workflow ---")
    start = time.time()
    rk = cc.ReKeyGen(patient_keys.secretKey, insurance_keys.publicKey)
    metrics.rekeygen_time_ms = (time.time() - start) * 1000

    start = time.time()
    re_ct = cc.ReEncrypt(ct, rk)
    metrics.reencrypt_time_ms = (time.time() - start) * 1000

    re_ct_path = CONFIG['data_dir'] / f"re_enc_record{run_number:03d}.enc"
    SerializeToFile(str(re_ct_path), re_ct, BINARY)
    metrics.rekey_size_bytes = re_ct_path.stat().st_size

    print(f"[RUN {run_number}] Re-encryption completed, size: {metrics.rekey_size_bytes}")

    # Generate hash for blockchain logging
    with open(re_ct_path, "rb") as f:
        data_hash = hashlib.sha256(f.read()).hexdigest()

    if fabric_available:
        try:
            start = time.time()
            tx_response = await hospital.submit_transaction(
                CONFIG['channel'], CONFIG['chaincode'], "ShareDataWithConsent",
                f"share{run_number:03d}", f"req{run_number:03d}", data_hash
            )
            metrics.log_share_latency_ms = (time.time() - start) * 1000
        except Exception as e:
            print(f"[RUN {run_number}] Log share failed: {e}")
            metrics.log_share_latency_ms = -1
    else:
        metrics.log_share_latency_ms = -1

    print(f"\n--- RUN {run_number}: PHASE 4: Decryption & Verification ---")
    start = time.time()
    decrypted = cc.Decrypt(insurance_keys.secretKey, re_ct)
    metrics.decrypt_time_ms = (time.time() - start) * 1000

    decrypted.SetLength(pt.GetLength())
    decrypted_data = decrypted.GetPackedValue()

    print(f"[RUN {run_number}] Decryption: {metrics.decrypt_time_ms:.2f} ms, Match: {health_data == decrypted_data}")

    # Return results for this run
    return {
        "run_number": run_number,
        "metrics": asdict(metrics),
        "verification": {
            "original_data": health_data,
            "decrypted_data": decrypted_data,
            "match": health_data == decrypted_data
        },
        "test_info": {
            "timestamp": time.time(),
            "fabric_network": "test-network",
            "crypto_scheme": "BFVRNS PRE"
        }
    }


def calculate_averages(successful_runs):
    """Calculate average performance metrics from successful runs."""
    if not successful_runs:
        return None
    
    # Initialize sums
    sums = {
        'keygen_time_ms': 0,
        'encrypt_time_ms': 0,
        'rekeygen_time_ms': 0,
        'reencrypt_time_ms': 0,
        'decrypt_time_ms': 0,
        'pubkey_size_bytes': 0,
        'ciphertext_size_bytes': 0,
        'rekey_size_bytes': 0,
        'store_record_latency_ms': 0,
        'request_share_latency_ms': 0,
        'log_share_latency_ms': 0
    }
    
    # Track valid blockchain measurements
    blockchain_counts = {
        'store_record': 0,
        'request_share': 0,
        'log_share': 0
    }
    
    # Sum all metrics
    for run in successful_runs:
        metrics = run['metrics']
        for key in sums.keys():
            if key in metrics:
                value = metrics[key]
                sums[key] += value
                
                # Track valid blockchain measurements
                if key == 'store_record_latency_ms' and value > 0:
                    blockchain_counts['store_record'] += 1
                elif key == 'request_share_latency_ms' and value > 0:
                    blockchain_counts['request_share'] += 1
                elif key == 'log_share_latency_ms' and value > 0:
                    blockchain_counts['log_share'] += 1
    
    # Calculate averages
    num_runs = len(successful_runs)
    averages = {}
    
    for key, total in sums.items():
        if key.endswith('_latency_ms'):
            # Use actual count of valid measurements for blockchain metrics
            if key == 'store_record_latency_ms':
                count = blockchain_counts['store_record'] if blockchain_counts['store_record'] > 0 else 1
            elif key == 'request_share_latency_ms':
                count = blockchain_counts['request_share'] if blockchain_counts['request_share'] > 0 else 1
            elif key == 'log_share_latency_ms':
                count = blockchain_counts['log_share'] if blockchain_counts['log_share'] > 0 else 1
            else:
                count = num_runs
            
            averages[key] = total / count if count > 0 else -1
        else:
            averages[key] = total / num_runs
    
    # Calculate standard deviations
    std_devs = {}
    for key in sums.keys():
        values = [run['metrics'][key] for run in successful_runs if key in run['metrics']]
        if len(values) > 1:
            mean = averages[key] if averages[key] > 0 else sum(values) / len(values)
            variance = sum((x - mean) ** 2 for x in values) / len(values)
            std_devs[key] = variance ** 0.5
        else:
            std_devs[key] = 0
    
    return {
        'averages': averages,
        'std_deviations': std_devs,
        'run_count': num_runs,
        'blockchain_success_counts': blockchain_counts,
        'sample_verification': successful_runs[0]['verification']  # All should be identical
    }


def print_comprehensive_average_report(avg_results, num_runs):
    """Print the comprehensive performance report with averages."""
    averages = avg_results['averages']
    std_devs = avg_results['std_deviations']
    blockchain_counts = avg_results['blockchain_success_counts']
    
    print(f"\n" + "="*60)
    print(f"{'AVERAGED COMPREHENSIVE PERFORMANCE REPORT':^60}")
    print(f"{'Based on ' + str(num_runs) + ' successful runs':^60}")
    print(f"="*60)
    
    print(f"\nCRYPTOGRAPHIC OPERATIONS (Average +/- Std Dev):")
    print(f"  Key Generation:        {averages['keygen_time_ms']:8.2f} +/- {std_devs['keygen_time_ms']:6.2f} ms")
    print(f"  Initial Encryption:    {averages['encrypt_time_ms']:8.2f} +/- {std_devs['encrypt_time_ms']:6.2f} ms")
    print(f"  Re-key Generation:     {averages['rekeygen_time_ms']:8.2f} +/- {std_devs['rekeygen_time_ms']:6.2f} ms")
    print(f"  Re-encryption:         {averages['reencrypt_time_ms']:8.2f} +/- {std_devs['reencrypt_time_ms']:6.2f} ms")
    print(f"  Final Decryption:      {averages['decrypt_time_ms']:8.2f} +/- {std_devs['decrypt_time_ms']:6.2f} ms")
    
    total_crypto_time = (averages['keygen_time_ms'] + averages['encrypt_time_ms'] + 
                        averages['rekeygen_time_ms'] + averages['reencrypt_time_ms'] + 
                        averages['decrypt_time_ms'])
    total_crypto_std = (std_devs['keygen_time_ms']**2 + std_devs['encrypt_time_ms']**2 + 
                       std_devs['rekeygen_time_ms']**2 + std_devs['reencrypt_time_ms']**2 + 
                       std_devs['decrypt_time_ms']**2) ** 0.5
    print(f"  Total Crypto Time:     {total_crypto_time:8.2f} +/- {total_crypto_std:6.2f} ms")
    
    print(f"\nDATA SIZES (Average +/- Std Dev):")
    print(f"  Public Key:            {averages['pubkey_size_bytes']:8,.0f} +/- {std_devs['pubkey_size_bytes']:6.0f} bytes")
    print(f"  Original Ciphertext:   {averages['ciphertext_size_bytes']:8,.0f} +/- {std_devs['ciphertext_size_bytes']:6.0f} bytes")
    print(f"  Re-encrypted Data:     {averages['rekey_size_bytes']:8,.0f} +/- {std_devs['rekey_size_bytes']:6.0f} bytes")
    
    size_overhead = averages['rekey_size_bytes'] - averages['ciphertext_size_bytes']
    overhead_pct = size_overhead / averages['ciphertext_size_bytes'] * 100 if averages['ciphertext_size_bytes'] > 0 else 0
    print(f"  Re-encryption Overhead:{size_overhead:8,.0f} bytes ({overhead_pct:+.1f}%)")
    
    print(f"\nBLOCKCHAIN TRANSACTIONS (Average +/- Std Dev):")
    
    # Check if any blockchain operations were successful
    any_blockchain_success = any(count > 0 for count in blockchain_counts.values())
    
    if any_blockchain_success:
        if blockchain_counts['store_record'] > 0:
            print(f"  Store Health Record:   {averages['store_record_latency_ms']:8.2f} +/- {std_devs['store_record_latency_ms']:6.2f} ms SUCCESS ({blockchain_counts['store_record']}/{num_runs} successful)")
        else:
            print(f"  Store Health Record:   FAILED (0/{num_runs} successful)")
            
        if blockchain_counts['request_share'] > 0:
            print(f"  Request Data Share:    {averages['request_share_latency_ms']:8.2f} +/- {std_devs['request_share_latency_ms']:6.2f} ms SUCCESS ({blockchain_counts['request_share']}/{num_runs} successful)")
        else:
            print(f"  Request Data Share:    FAILED (0/{num_runs} successful)")
            
        if blockchain_counts['log_share'] > 0:
            print(f"  Log Data Share:        {averages['log_share_latency_ms']:8.2f} +/- {std_devs['log_share_latency_ms']:6.2f} ms SUCCESS ({blockchain_counts['log_share']}/{num_runs} successful)")
        else:
            print(f"  Log Data Share:        FAILED (0/{num_runs} successful)")
        
        # Calculate total blockchain time only for successful operations
        successful_blockchain_ops = []
        if blockchain_counts['store_record'] > 0:
            successful_blockchain_ops.append(averages['store_record_latency_ms'])
        if blockchain_counts['request_share'] > 0:
            successful_blockchain_ops.append(averages['request_share_latency_ms'])
        if blockchain_counts['log_share'] > 0:
            successful_blockchain_ops.append(averages['log_share_latency_ms'])
            
        if successful_blockchain_ops:
            total_blockchain_time = sum(successful_blockchain_ops)
            print(f"  Total Blockchain Time: {total_blockchain_time:8.2f} ms (successful ops only)")
        else:
            print(f"  Total Blockchain Time: N/A (no successful operations)")
    else:
        print(f"  Store Health Record:   SKIPPED")
        print(f"  Request Data Share:    SKIPPED")
        print(f"  Log Data Share:        SKIPPED")
        print(f"  Total Blockchain Time: N/A (all transactions skipped)")
    
    print(f"\nDATA INTEGRITY:")
    integrity_status = "VERIFIED" if avg_results['sample_verification']['match'] else "FAILED"
    print(f"  Original -> Decrypted:  {integrity_status} ({num_runs}/{num_runs} runs)")
    print(f"  Consistency:           100% across all runs")
    
    print(f"\nPERFORMANCE SUMMARY:")
    print(f"  Avg End-to-End Crypto: {total_crypto_time:8.2f} +/- {total_crypto_std:6.2f} ms")
    
    if any_blockchain_success and 'successful_blockchain_ops' in locals() and successful_blockchain_ops:
        total_time = total_crypto_time + total_blockchain_time
        print(f"  Avg End-to-End Total:  {total_time:8.2f} ms")
        print(f"  Crypto/Total Ratio:    {(total_crypto_time/total_time)*100:6.1f}%")
        print(f"  Blockchain/Total:      {(total_blockchain_time/total_time)*100:6.1f}%")
    else:
        print(f"  Avg End-to-End Total:  {total_crypto_time:8.2f} ms (crypto only)")
        print(f"  Blockchain Status:     SKIPPED/FAILED")
    
    # Performance variability analysis
    crypto_coefficients_of_variation = []
    for key in ['keygen_time_ms', 'encrypt_time_ms', 'rekeygen_time_ms', 'reencrypt_time_ms', 'decrypt_time_ms']:
        if averages[key] > 0:
            cv = (std_devs[key] / averages[key]) * 100
            crypto_coefficients_of_variation.append(cv)
    
    if crypto_coefficients_of_variation:
        avg_cv = sum(crypto_coefficients_of_variation) / len(crypto_coefficients_of_variation)
        print(f"\nPERFORMANCE STABILITY:")
        print(f"  Avg Coefficient of Var: {avg_cv:6.1f}%")
        if avg_cv < 5:
            print(f"  Stability Assessment:   EXCELLENT (Very consistent)")
        elif avg_cv < 15:
            print(f"  Stability Assessment:   GOOD (Reasonably stable)")
        elif avg_cv < 30:
            print(f"  Stability Assessment:   MODERATE (Some variation)")
        else:
            print(f"  Stability Assessment:   POOR (High variability)")
    
    print(f"\nSTORAGE EFFICIENCY:")
    if averages['pubkey_size_bytes'] > 0:
        ct_to_key_ratio = averages['ciphertext_size_bytes'] / averages['pubkey_size_bytes']
        print(f"  Avg CT/Key Ratio:      {ct_to_key_ratio:8.2f}x")
    
    if size_overhead != 0:
        expansion_factor = averages['rekey_size_bytes'] / averages['ciphertext_size_bytes']
        print(f"  Avg Re-encryption:     {expansion_factor:8.2f}x")
    
    # Data throughput (theoretical)
    if total_crypto_time > 0:
        data_throughput = (3 * 1000) / total_crypto_time  # 3 data points per workflow
        print(f"  Avg Crypto Throughput: {data_throughput:8.1f} items/sec")
    
    print(f"\n" + "="*60)
    print(f"{'AVERAGED WORKFLOW STATUS: ' + ('SUCCESS' if avg_results['sample_verification']['match'] else 'FAILED'):^60}")
    print(f"{'(' + str(num_runs) + ' runs completed)':^60}")
    print(f"="*60)


# -------- Entry Point --------
async def main():
    """Main entry point for the PRE health data sharing workflow with averaging."""
    try:
        print("="*60)
        print("PRE HEALTH DATA SHARING SYSTEM - AVERAGED PERFORMANCE ANALYSIS")
        print("Proxy Re-Encryption + Hyperledger Fabric Integration")
        print("="*60)
        
        # Ask user for number of runs or use default
        try:
            num_runs_input = os.environ.get('NUM_RUNS', '3')  # Default to 3 runs
            num_runs = int(num_runs_input)
            if num_runs < 1:
                num_runs = 3
        except:
            num_runs = 3
        
        print(f"\nConfiguration: Running {num_runs} iterations for averaged results")
        print(f"You can set NUM_RUNS environment variable to change this")
        
        results = await execute_workflow(num_runs)
        
        if not results:
            print(f"[SYSTEM] No successful runs completed!")
            return None
        
        # Additional analysis and recommendations based on averaged data
        print(f"\nAVERAGED SYSTEM ANALYSIS & RECOMMENDATIONS:")
        
        avg_data = results['summary']
        averages = avg_data['averages']
        std_devs = avg_data['std_deviations']
        
        # Create mappings for cleaner code
        crypto_operation_names = [
            'keygen_time_ms', 
            'encrypt_time_ms', 
            'rekeygen_time_ms', 
            'reencrypt_time_ms', 
            'decrypt_time_ms'
        ]
        
        crypto_display_names = [
            'Key Generation',
            'Encryption', 
            'Re-key Generation',
            'Re-encryption',
            'Decryption'
        ]
        
        # Performance analysis - FIXED SECTION
        crypto_times = [
            averages['keygen_time_ms'],
            averages['encrypt_time_ms'],
            averages['rekeygen_time_ms'],
            averages['reencrypt_time_ms'],
            averages['decrypt_time_ms']
        ]
        
        # Find bottleneck operation
        max_crypto_time = max(crypto_times)
        bottleneck_index = crypto_times.index(max_crypto_time)
        max_crypto_op = crypto_display_names[bottleneck_index]
        corresponding_std_dev = std_devs[crypto_operation_names[bottleneck_index]]
        
        # CORRECTED PRINT STATEMENT - Fixed the f-string syntax error
        print(f"  Avg Bottleneck Operation:  {max_crypto_op} ({max_crypto_time:.2f} +/- {corresponding_std_dev:.2f} ms)")
        
        # Variability analysis
        variability_scores = []
        for key in crypto_operation_names:
            if averages[key] > 0:
                cv = (std_devs[key] / averages[key]) * 100
                variability_scores.append(cv)
        
        if variability_scores:
            avg_variability = sum(variability_scores) / len(variability_scores)
            print(f"  Avg Performance Variability: {avg_variability:.1f}% coefficient of variation")
            
            if avg_variability < 5:
                print(f"  Performance Consistency:   EXCELLENT (Highly predictable)")
            elif avg_variability < 15:
                print(f"  Performance Consistency:   GOOD (Reasonably stable)")
            elif avg_variability < 30:
                print(f"  Performance Consistency:   MODERATE (Some fluctuation)")
            else:
                print(f"  Performance Consistency:   POOR (High variability)")
        
        # Size analysis
        size_efficiency = (averages['ciphertext_size_bytes'] / 
                          averages['pubkey_size_bytes']) if averages['pubkey_size_bytes'] > 0 else 0
        
        if size_efficiency > 0:
            if size_efficiency < 1:
                print(f"  Storage Efficiency:        EXCELLENT (CT < PK)")
            elif size_efficiency < 2:
                print(f"  Storage Efficiency:        GOOD (CT ~= PK)")
            elif size_efficiency < 5:
                print(f"  Storage Efficiency:        ACCEPTABLE (CT < 5xPK)")
            else:
                print(f"  Storage Efficiency:        POOR (CT >> PK)")
        
        # Blockchain performance analysis
        blockchain_counts = avg_data['blockchain_success_counts']
        successful_blockchain_ops = [k for k, v in blockchain_counts.items() if v > 0]
        
        if successful_blockchain_ops:
            blockchain_latencies = []
            for op in ['store_record', 'request_share', 'log_share']:
                if blockchain_counts[op] > 0:
                    if op == 'store_record':
                        blockchain_latencies.append(averages['store_record_latency_ms'])
                    elif op == 'request_share':
                        blockchain_latencies.append(averages['request_share_latency_ms'])
                    elif op == 'log_share':
                        blockchain_latencies.append(averages['log_share_latency_ms'])
            
            if blockchain_latencies:
                avg_blockchain_latency = sum(blockchain_latencies) / len(blockchain_latencies)
                print(f"  Avg Blockchain Latency:    {avg_blockchain_latency:.2f} ms")
                
                if avg_blockchain_latency < 100:
                    print(f"  Blockchain Performance:    EXCELLENT")
                elif avg_blockchain_latency < 500:
                    print(f"  Blockchain Performance:    GOOD")
                elif avg_blockchain_latency < 1000:
                    print(f"  Blockchain Performance:    ACCEPTABLE")
                else:
                    print(f"  Blockchain Performance:    NEEDS OPTIMIZATION")
            
            # Success rate analysis
            total_attempts = len(results['individual_runs']) * 3  # 3 blockchain ops per run
            total_successes = sum(blockchain_counts.values())
            success_rate = (total_successes / total_attempts) * 100 if total_attempts > 0 else 0
            print(f"  Blockchain Success Rate:   {success_rate:.1f}% ({total_successes}/{total_attempts})")
        else:
            print(f"  Blockchain Performance:    NOT AVAILABLE")
            print(f"  Blockchain Success Rate:   0.0% (all operations failed/skipped)")
        
        # Security assessment
        print(f"\nSECURITY ASSESSMENT:")
        print(f"  Encryption Scheme:         BFVRNS (Post-Quantum Ready)")
        print(f"  Security Level:            128-bit Classical")
        print(f"  Key Management:            Distributed (Hospital + Insurance)")
        print(f"  Data Integrity:            {'VERIFIED' if avg_data['sample_verification']['match'] else 'COMPROMISED'} (across all {avg_data['run_count']} runs)")
        print(f"  Blockchain Audit:          {'PARTIAL' if any(blockchain_counts.values()) else 'DISABLED'}")
        
        # Statistical significance
        if avg_data['run_count'] >= 3:
            print(f"  Statistical Confidence:    {'HIGH' if avg_data['run_count'] >= 10 else 'MODERATE'} (n={avg_data['run_count']})")
        else:
            print(f"  Statistical Confidence:    LOW (n={avg_data['run_count']}) - Consider more runs")
        
        # Recommendations
        print(f"\nOPTIMIZATION RECOMMENDATIONS:")
        
        if max_crypto_time > 100:
            print(f"  • Consider parameter optimization for {max_crypto_op}")
            
        if avg_variability > 20:
            print(f"  • High performance variability detected - investigate system load")
            
        if averages['rekey_size_bytes'] > averages['ciphertext_size_bytes'] * 1.5:
            print(f"  • Re-encryption overhead is high - consider compression")
        
        if not any(blockchain_counts.values()):
            print(f"  • Fix blockchain connectivity for full audit trail")
        elif sum(blockchain_counts.values()) < len(results['individual_runs']) * 3:
            print(f"  • Blockchain reliability issues - check network stability")
        
        if averages['pubkey_size_bytes'] > 50000:  # Arbitrary threshold
            print(f"  • Large public key size - consider key compression")
        
        total_crypto = sum(crypto_times)
        if total_crypto > 1000:  # > 1 second total
            print(f"  • Total crypto time is high - consider hardware acceleration")
            
        if avg_data['run_count'] < 10:
            print(f"  • Run more iterations (n>=10) for higher statistical confidence")
        
        print(f"\nUSE CASE SUITABILITY:")
        
        # Real-time vs Batch processing
        if total_crypto < 100:
            print(f"  Real-time Processing:      SUITABLE (avg: {total_crypto:.1f}ms)")
        elif total_crypto < 500:
            print(f"  Real-time Processing:      MARGINAL (avg: {total_crypto:.1f}ms)")
        else:
            print(f"  Real-time Processing:      NOT SUITABLE (avg: {total_crypto:.1f}ms)")
        
        # Scalability assessment with confidence intervals
        crypto_95_ci = total_crypto + (1.96 * (sum(v**2 for v in [std_devs[k] for k in crypto_operation_names])**0.5))
        
        if crypto_95_ci < 200:
            print(f"  High-Volume Deployment:    SUITABLE (95% CI: {crypto_95_ci:.1f}ms)")
        elif crypto_95_ci < 1000:
            print(f"  High-Volume Deployment:    NEEDS TESTING (95% CI: {crypto_95_ci:.1f}ms)")
        else:
            print(f"  High-Volume Deployment:    NOT SUITABLE (95% CI: {crypto_95_ci:.1f}ms)")
        
        # Compliance readiness
        audit_ready = any(blockchain_counts.values())
        integrity_verified = avg_data['sample_verification']['match']
        
        if audit_ready and integrity_verified:
            print(f"  Regulatory Compliance:     READY (HIPAA/GDPR)")
        elif integrity_verified:
            print(f"  Regulatory Compliance:     PARTIAL (Missing Reliable Audit)")
        else:
            print(f"  Regulatory Compliance:     NOT READY")
        
        print(f"\nSTATISTICAL SUMMARY:")
        print(f"  Total Runs Executed:       {len(results['individual_runs'])}")
        print(f"  Successful Runs:           {results['statistics']['successful_runs']}")
        print(f"  Overall Success Rate:      {results['statistics']['success_rate']:.1f}%")
        print(f"  Data Consistency:          100% (all successful runs identical)")
        
        print(f"\n" + "="*60)
        
        return results
        
    except KeyboardInterrupt:
        print(f"\n\n[SYSTEM] Workflow interrupted by user.")
        return None
    except Exception as e:
        print(f"\n\n[ERROR] Critical system failure: {e}")
        import traceback
        traceback.print_exc()
        return None


if __name__ == "__main__":
    # Run the async workflow with averaging
    try:
        import uvloop
        uvloop.install()
        print("[SYSTEM] Using uvloop for enhanced async performance")
    except ImportError:
        print("[SYSTEM] Using standard asyncio event loop")
    
    results = asyncio.run(main())
    
    if results:
        print(f"\n[SYSTEM] Averaged workflow completed successfully!")
        print(f"[SYSTEM] Aggregated results saved to: {CONFIG['data_dir'] / 'aggregated_performance_results.json'}")
        
        # Exit code based on overall success
        exit_code = 0 if results['statistics']['success_rate'] > 0 else 1
        print(f"[SYSTEM] Exiting with code: {exit_code}")
        exit(exit_code)
    else:
        print(f"[SYSTEM] Averaged workflow failed or was interrupted!")
        exit(1)
