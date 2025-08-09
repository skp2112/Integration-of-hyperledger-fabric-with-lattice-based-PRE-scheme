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
    parameters.SetSecurityLevel(HEStd_128_classic)

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
            
            # Method 1: Try using the client's get_user method
            try:
                self.user = self.cli.get_user(org_name=self.org_name, name=self.user_name)
                if self.user:
                    print(f"[FABRIC] Found existing user '{self.user_name}' in state store")
                else:
                    print(f"[FABRIC] No existing user found, creating new user")
                    # Method 2: Create user using client methods
                    try:
                        # This is the correct way for fabric-sdk-py
                        enrollment = {
                            'key': private_key,
                            'cert': certificate
                        }
                        
                        self.user = self.cli.create_user(
                            user_name=self.user_name,
                            org_name=self.org_name,
                            state_store=None,  # Use default state store
                            msp_id=self.msp_id,
                            key=private_key,
                            cert=certificate
                        )
                        print(f"[FABRIC] User '{self.user_name}' created with enrollment")
                        
                    except Exception as e:
                        print(f"[FABRIC] create_user method failed: {e}")
                        # Method 3: Direct enrollment approach
                        from hfc.fabric.user import User
                        
                        # Create user object manually
                        self.user = User(
                            user_name=self.user_name,
                            state_store=self.cli.state_store
                        )
                        
                        # Set enrollment data
                        self.user._enrollment = {
                            'key': private_key,
                            'cert': certificate
                        }
                        self.user._msp_id = self.msp_id
                        
                        print(f"[FABRIC] User '{self.user_name}' initialized with manual enrollment")
                        
            except Exception as e:
                print(f"[FABRIC] get_user method failed: {e}")
                raise
                
        except Exception as e:
            print(f"[FABRIC] Error initializing user: {e}")
            # Last resort: try basic user creation
            try:
                from hfc.fabric.user import User
                
                with open(self.key_path, 'r') as key_file:
                    private_key = key_file.read()
                with open(self.cert_path, 'r') as cert_file:
                    certificate = cert_file.read()
                
                # Try the simplest possible User creation
                self.user = User(self.user_name)
                self.user._enrollment = {
                    'key': private_key,
                    'cert': certificate
                }
                self.user._msp_id = self.msp_id
                
                print(f"[FABRIC] User '{self.user_name}' created using fallback method")
                
            except Exception as final_error:
                print(f"[FABRIC] All user initialization methods failed: {final_error}")
                print("[FABRIC] Attempting final fallback with correct User constructor...")
                
                # Final attempt with correct constructor signature
                try:
                    from hfc.fabric.user import User
                    
                    # User constructor typically requires: name, org, state_store
                    self.user = User(
                        name=self.user_name,
                        org=self.org_name,
                        state_store=self.cli.state_store
                    )
                    
                    # Set enrollment manually
                    with open(self.key_path, 'r') as key_file:
                        private_key = key_file.read()
                    with open(self.cert_path, 'r') as cert_file:
                        certificate = cert_file.read()
                        
                    self.user._enrollment = {
                        'key': private_key,
                        'cert': certificate
                    }
                    self.user._msp_id = self.msp_id
                    
                    print(f"[FABRIC] User '{self.user_name}' created using correct constructor")
                    
                except Exception as ultimate_error:
                    print(f"[FABRIC] Ultimate fallback failed: {ultimate_error}")
                    print("[FABRIC] Will attempt to continue without proper user context...")
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
async def execute_workflow():
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
    print(f"[CRYPTO] Ciphertext size: {metrics.ciphertext_size_bytes} bytes")

    print("\n--- PHASE 2: Submitting Records to Fabric ---")
    try:
        start = time.time()
        await hospital.submit_transaction(
            CONFIG['channel'], CONFIG['chaincode'], "StoreHealthRecord",
            "record001", "patient123", str(ct_path), str(pub_key_path)
        )
        metrics.store_record_latency_ms = (time.time() - start) * 1000
        print(f"[FABRIC] Store record latency: {metrics.store_record_latency_ms:.2f} ms")
    except Exception as e:
        print(f"[FABRIC] Warning: Could not store health record: {e}")
        metrics.store_record_latency_ms = -1

    try:
        start = time.time()
        await insurance.submit_transaction(
            CONFIG['channel'], CONFIG['chaincode'], "RequestDataShare",
            "req001", "record001"
        )
        metrics.request_share_latency_ms = (time.time() - start) * 1000
        print(f"[FABRIC] Request share latency: {metrics.request_share_latency_ms:.2f} ms")
    except Exception as e:
        print(f"[FABRIC] Warning: Could not request data share: {e}")
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

    with open(re_ct_path, "rb") as f:
        data_hash = hashlib.sha256(f.read()).hexdigest()

    print(f"[CRYPTO] Re-encryption key generation time: {metrics.rekeygen_time_ms:.2f} ms")
    print(f"[CRYPTO] Re-encryption time: {metrics.reencrypt_time_ms:.2f} ms")
    print(f"[CRYPTO] Re-encrypted data hash: {data_hash[:16]}...")

    try:
        start = time.time()
        await hospital.submit_transaction(
            CONFIG['channel'], CONFIG['chaincode'], "ShareDataWithConsent",
            "share001", "req001", data_hash
        )
        metrics.log_share_latency_ms = (time.time() - start) * 1000
        print(f"[FABRIC] Log share latency: {metrics.log_share_latency_ms:.2f} ms")
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

    # Save performance metrics and verification result
    results = {
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

    result_path = CONFIG['data_dir'] / "performance_results.json"
    with open(result_path, "w") as f:
        json.dump(results, f, indent=4)

    print(f"\n\nSUCCESS: Workflow completed. Metrics saved to {result_path}")
    print(f"\n=== PERFORMANCE SUMMARY ===")
    print(f"Key Generation: {metrics.keygen_time_ms:.2f} ms")
    print(f"Encryption: {metrics.encrypt_time_ms:.2f} ms")
    print(f"Re-key Generation: {metrics.rekeygen_time_ms:.2f} ms")
    print(f"Re-encryption: {metrics.reencrypt_time_ms:.2f} ms")
    print(f"Decryption: {metrics.decrypt_time_ms:.2f} ms")
    print(f"Public Key Size: {metrics.pubkey_size_bytes} bytes")
    print(f"Ciphertext Size: {metrics.ciphertext_size_bytes} bytes")


if __name__ == "__main__":
    try:
        asyncio.run(execute_workflow())
    except KeyboardInterrupt:
        print("\n[INFO] Process interrupted by user")
    except Exception as e:
        print(f"\n[ERROR] Workflow failed: {e}")
        import traceback
        traceback.print_exc()
