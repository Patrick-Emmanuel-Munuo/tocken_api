
# 🔐 Utility Token Generator API (STS-like)

This project implements a Flask-based API to generate **secure utility tokens** using an algorithm similar to the **Standard Transfer Specification (STS)** used in prepaid metering systems. It includes token block construction, CRC-16 checksum, mantissa/exponent calculation, and DES encryption.

---

## 📦 Features

- Generate 64-bit token blocks based on units
- Calculate CRC-16 checksums
- Support exponent/mantissa-based value encoding
- DES ECB encryption for secure token transformation
- Decoder key generation from standard STS fields
- API endpoint to generate final 20-digit token
- CORS-enabled for frontend integration

---

## 🧰 Technologies Used

- Python 3.x
- Flask
- Flask-CORS
- PyCryptodome (`Crypto.Cipher.DES`)
- Standard Python libraries (`datetime`, `math`, `random`, etc.)

---

## 🚀 Getting Started

### 📋 Prerequisites

- Python 3.8+
- Pip

### 🔧 Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/your-username/utility-token-generator.git
   cd utility-token-generator
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the server**:
   ```bash
   python app.py
   ```

   The API will run on: `http://localhost:1000`

---

## 🔄 API Endpoint

### `GET /generate_token`

Generates a secure utility token for a specified unit amount.

#### Query Parameters:

| Parameter | Type   | Required | Description                  |
|-----------|--------|----------|------------------------------|
| units     | float  | Yes      | Amount of energy in kWh      |

#### Example Request:

```http
GET /generate_token?units=45.5
```

#### Response:

```json
{
  "success": true,
  "message": {
    "token_data": {
      "exponent": 1,
      "mantissa": 2345,
      "units": 45.5,
      "cls": "00",
      "subclass": "0000",
      "rnd_block": "1101",
      "tid_block": "101001001011010010101010",
      "crc_block": "1010101010101010",
      "token_64_bit_block": "000011011010010010110100101010100010101011010101010101010101010"
    },
    "utility_token": {
      "success": true,
      "message": "1234-5678-9012-3456-7890"
    }
  }
}
```

---

## 🔐 Token Generation Logic Overview

1. **Input Units** → Exponent & Mantissa
2. **Create Token Block**:
   - Class + Subclass (6 bits)
   - Random bits (4 bits)
   - TID (Time in minutes since 2012-01-01)
   - Amount block (Exponent + Mantissa = 16 bits)
   - Total: 50 bits
3. **Calculate CRC-16** on 50-bit block → 16-bit CRC
4. **Final Token Block**: 50 bits + 16-bit CRC = 66 bits
5. **Encrypt** 64-bit block using **DES (ECB mode)** and generated decoder key
6. **Convert** final binary to **20-digit token**

---

## 🛠 Configuration

Some values are hardcoded in the script but can be extracted into configuration files if needed:

| Parameter                | Value       | Description                     |
|--------------------------|-------------|---------------------------------|
| `token_class`            | 0           | Token type                      |
| `token_sub_class`        | 0           | Token subcategory               |
| `base_date`              | 2012-01-01  | Used for TID calculation        |
| `key_type`               | 01          | Key type code                   |
| `supply_group_code`      | 1234        | Supply group identifier         |
| `tariff_index`           | 01          | Tariff index code               |
| `key_revision_number`    | 00          | Revision/version of the key     |
| `decoder_reference_number` | 1234567890 | Unique DRN used for encryption  |

---

## 📁 Project Structure

```
├── app.py              # Main Flask application
├── README.md           # Project documentation
└── requirements.txt    # Required Python libraries
```
---
## 📁 Run with modemon 
```
nodemon --exec python encript.py
```
---

## ✅ Dependencies

Add the following to `requirements.txt`:

```
Flask
Flask-Cors
pycryptodome
```

Install with:

```bash
pip install -r requirements.txt
```

---

## 🔒 Security Notes

- **DES** is used per STS protocol standards but is outdated for modern cryptographic use. Do not use this as-is for new secure systems.
- Make sure to secure this API in production and restrict access appropriately.

---

## 📄 License

This project is provided for **educational and prototyping purposes only**. Commercial or production use is at your own risk.
