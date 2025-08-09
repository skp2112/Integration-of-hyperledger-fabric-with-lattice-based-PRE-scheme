# Post-Quantum secure Health Insurance Scheme based on Hyperledger Fabric

## Project Summary
A comprehensive integration of lattice-based cryptography (OpenFHE BFVRNS PRE) with Hyperledger Fabric, featuring secure proxy re-encryption and data sharing in healthcare environments. The system includes **multi-run performance analysis with statistical averaging** to provide reliable benchmarking results. Written in Python using the Fabric Python SDK with detailed performance metrics and comprehensive reporting.

***


### Multi-Run Performance Analysis
- **Statistical Averaging**: Executes multiple workflow iterations (default: 3 runs) for reliable performance metrics
- **Standard Deviation Calculation**: Provides performance variability analysis with confidence intervals  
- **Comprehensive Reporting**: Generates detailed performance reports with averages, standard deviations, and recommendations
- **Automated Analysis**: Includes bottleneck identification, stability assessment, and suitability analysis

### Available Applications
- `main_app.py`: Single-run execution for basic testing
- `main_app_new.py`: **Enhanced multi-run analysis with statistical reporting** (recommended for benchmarking)

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

`` fabric-samples/
└── chaincode/
└── pre-health/
├── main_app.py # Single-run basic version
├── main_app_new.py # Enhanced multi-run statistical version
├── README.md
├── .fabricignore
└── fabric_performance_data/
├── aggregated_performance_results.json # Statistical summary
├── performance_results_run_*.json # Individual run data
└── *.enc, *.key files # Generated crypto files
***

## Running Your Workflow

1. Start Fabric network and deploy chaincode.
2. Activate Python environment and export variables.
3. Run:
   ```
   cd ~/fabric-workspace/fabric-samples/chaincode/pre-health/
   python3 main_app.py/python3 main_app_new.py ##for single run or multiple run for average performance
   ```
4. Outputs in `fabric_performance_data/`.

***

## Notes & Known Issues
- Fabric client user init may require manual MSP cert loading.
### Fabric Integration
- Fabric client user initialization may require manual MSP certificate loading due to SDK version variations
- Blockchain transactions may be skipped if user initialization fails - crypto operations continue normally
- Ensure Fabric test network is running before executing workflows

### Performance Analysis
- **Multi-run version recommended** for reliable benchmarking results
- Minimum 3 runs suggested for statistical significance (10+ runs for high confidence)
- Runtime files (*.enc, *.key) are auto-generated and excluded from version control via `.fabricignore`
- Individual run data preserved in separate JSON files for detailed analysis

### System Requirements
- Sufficient disk space for multiple encrypted file generations
- Consistent system load recommended during multi-run analysis for reliable results

## License


