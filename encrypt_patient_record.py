from openfhe import *
from pathlib import Path


parameters = CCParamsBFVRNS()
parameters.SetPlaintextModulus(65537)
parameters.SetMultiplicativeDepth(1)
parameters.SetSecurityLevel(HEStd_128_classic)

cc = GenCryptoContext(parameters)

cc.Enable(PKESchemeFeature.PKE)
cc.Enable(PKESchemeFeature.KEYSWITCH)
cc.Enable(PKESchemeFeature.LEVELEDSHE)
cc.Enable(PKESchemeFeature.PRE)

# Generate keys for patient
key_pair = cc.KeyGen()

# Sample health data: Systolic BP, Diastolic BP, Pulse Rate
health_data = [120, 80, 366]

# Create plaintext and encrypt
pt = cc.MakePackedPlaintext(health_data)
ct = cc.Encrypt(key_pair.publicKey, pt)

# File paths to save encrypted data and public key
data_dir = Path("fabric_performance_data")
ct_path = data_dir / "record001.enc"
pubkey_path = data_dir / "patient_pubkey.key"

# Serialize data to files
SerializeToFile(str(ct_path), ct, BINARY)
SerializeToFile(str(pubkey_path), key_pair.publicKey, BINARY)

print(f"Encrypted health record saved at: {ct_path}")
print(f"Patient public key saved at: {pubkey_path}")
