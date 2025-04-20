# 🗝 DES (Data Encryption Standard)

![made-with-python](https://img.shields.io/badge/Made%20with-Python%203-1f425f.svg)

## Introduction

The __Data Encryption Standard (DES)__ is a symmetric-key block cipher published by the __National Institute of
Standards and Technology (NIST)__. Here, DES has been implemented in Python 3 with no other dependencies. A full
explanation of the cipher along with the Code can be seen in this
[Jupyter Notebook](notebook/data-encryption-standard-des.ipynb).

The DES structure uses many smaller Ciphers such as the single Round Fiestel Cipher, which in turn uses the
single Swapper and Mixer Ciphers. All of these smaller constructs have lso been built in individual classes and these
smaller constructs have been composed together to form the DES Algorithm.

These smaller Ciphers can also be used individual or composed together to create different Ciphers. These building
blocks are:

- [P-Boxes (Permutation Boxes)](des/PBox.py)
- [S-Boxes (Substitution Boxes)](des/SBox.py)
- [Swapper Cipher](des/Swapper.py)
- [Mixer Cipher](des/Mixer.py)
- [Single Round Fiestel Cipher](des/Round.py)
- [DES (Data Encryption Standard)](des/DES.py)

## Running It Locally

Clone this repository to your machine and navigate to the `DES_455` directory:

```bash
git clone https://github.com/RobinCC24/DES_455.git
cd DES_455
```

Install the required dependencies:

```bash
pip install -r requirements.txt
```

Modify the input in `driver.py` and run it for fast encryption/decryption. Alternatively, use `app.py` for a web-based
interface:

```bash
python driver.py
```

```bash
python app.py
```

## References

1. [Data Encryption Standard – Wikipedia](https://en.wikipedia.org/wiki/Data_Encryption_Standard)
2. [Data Encryption Standard – TutorialsPoint](https://www.tutorialspoint.com/cryptography/data_encryption_standard.htm)
3. *Cryptography and Network Security* – Behrouz A.
   Forouzan ([Google Books](https://books.google.co.in/books?id=OYiwCgAAQBAJ))
4. [ChatGPT – OpenAI](https://chatgpt.com)
