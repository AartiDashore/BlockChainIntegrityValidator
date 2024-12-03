# **Blockchain Integrity Validator**
Bitcoin Block Manipulation &amp; Verification  

## **Overview**  
Blockchain Integrity Validator is a Python-based project designed to interact with the Bitcoin blockchain by retrieving, analyzing, and manipulating blocks to simulate and demonstrate tamper detection mechanisms. This program connects to the Bitcoin network using TCP/IP and performs operations without relying on external blockchain libraries, ensuring a deeper understanding of blockchain protocols and cryptographic structures.  


## **Features**  
- Retrieve Bitcoin blockchain blocks using a block number derived from SU ID modulo 10,000.  
- Display transaction details of retrieved blocks.  
- Simulate tampering by modifying transaction outputs and recalculating Merkle-tree hashes to maintain updated block data.  
- Generate automated reports comparing the original and tampered blocks to illustrate blockchain peer rejection of altered data.  


## **Technologies Used**  
- **Programming Language**: Python 3  
- **Protocols**: TCP/IP for peer-to-peer communication  
- **Cryptography**: Hashing and Merkle-tree operations  


## **How It Works**  
1. **Block Retrieval**:  
   - Connect to a full node in the Bitcoin network via TCP/IP.  
   - Retrieve the block corresponding to your SU ID modulo 10,000.  

2. **Transaction Display**:  
   - Parse and display the transactions contained in the block (Extra Credit).  

3. **Tamper Simulation**:  
   - Modify a transaction's output and recalculate all related cryptographic data, including the Merkle-tree hashes (Extra Credit).  

4. **Report Generation**:  
   - Compare the original and tampered block hashes.  
   - Highlight how the altered block would be detected and rejected by network peers.  


## **Getting Started**  
### **Prerequisites**  
- Python 3.8 or higher  
- No additional libraries required  

### **Installation**  
1. Clone the repository:  
   ```bash  
   git clone https://github.com/yourusername/blockchain-integrity-validator.git  
   cd blockchain-integrity-validator  
   ```  

2. Run the program:  
   ```bash  
   python3 blockchain_validator.py  
   ```  


## **Future Enhancements**  
- Support for multi-block manipulation and validation.  
- Enhanced visualization for transaction and block tampering reports.  


## **License**  
This project is open-source and available under the [MIT License](LICENSE).  


## **Acknowledgments**  
Inspired by blockchain cryptography principles and academic requirements at Seattle University.
