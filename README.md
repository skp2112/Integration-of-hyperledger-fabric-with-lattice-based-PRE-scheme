```
# Post-Quantum secure Health Insurance Scheme based on Hyperledger Fabric

## Project Summary

A full-stack integration of lattice-based cryptography (OpenFHE BFVRNS PRE) with Hyperledger Fabric, enabling secure proxy re-encryption and data sharing in a healthcare environment. Written in Python and using the Fabric Python SDK.

***

## Platform & Environment Setup

### 1. **Operating System**
- Recommended: Ubuntu 20.04+ (Linux; tested on Ubuntu 18.04, 20.04)
- Other requirements: Docker, cURL, Git.

### 2. **Fabric Test Network**
- Clone official samples:
  ```
  git clone https://github.com/hyperledger/fabric-samples.git
  cd fabric-samples/test-network
  ```
- Launch the network and deploy chaincode:
  ```
  ./network.sh up createChannel -c mychannel
  ./network.sh deployCC -c mychannel -ccn prehealth -ccp ../chaincode/pre-health/ -ccl go
  ```

### 3. **Python Virtual Environment**
- Install Python 3.11+:
  ```
  sudo apt-get update
  sudo apt-get install python3.11 python3.11-venv python3.11-dev libssl-dev
  ```
- Create & activate venv:
  ```
  python3.11 -m venv ~/openfhe-python/venv311
  source ~/openfhe-python/venv311/bin/activate
  ```
- *(Store virtualenv OUTSIDE the Fabric chaincode folders to avoid packaging errors.)*

### 4. **Fabric Python SDK**
- Install via pip or build from source:
  ```
  pip install fabric-sdk-py
  ```
- Pre-requisite: `libssl-dev`, `python3.11-dev`, `virtualenv`.

### 5. **OpenFHE Python Bindings**
- Build and install OpenFHE Python bindings.
  - Typical build location: `~/openfhe-python/build`
  - Set environment variable each session before running:
    ```
    export PYTHONPATH=~/openfhe-python/build:$PYTHONPATH
    export LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libstdc++.so.6
    ```

### 6. **Other Python Libraries**
```
pip install asyncio dataclasses openfhe
```

***

## Project Folder Structure

```
fabric-samples/
└── chaincode/
    └── pre-health/
        ├── main_app.py
        ├── README.md
        ├── .fabricignore
        └── fabric_performance_data/
```

***

## Running Your Workflow

1. Start Fabric network and deploy chaincode.
2. Activate Python environment and export variables.
3. Run:
   ```
   cd ~/fabric-workspace/fabric-samples/chaincode/pre-health/
   python3 main_app.py
   ```
4. Outputs in `fabric_performance_data/`.

***

## Notes & Known Issues
- Fabric client user init may require manual MSP cert loading.
- Exclude `venv` in `.fabricignore`.

## License

```
```

***
