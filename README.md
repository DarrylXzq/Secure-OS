# Principles of Secure Operating Systems
> [!IMPORTANT]
> `Principles of Secure Operating Systems` project developed a file encryption software to ensure data security and integrity through AES-CBC encryption and SHA-256 integrity verification. The software is implemented in C with the OpenSSL library on Minix OS, enhancing the system's security performance.

<div align="left">
  <img src="https://img.shields.io/badge/-C-blue.svg">
  <img src="https://img.shields.io/badge/-OpenSSL-green.svg">
  <img src="https://img.shields.io/badge/-Minix_OS-orange.svg">
  <img src="https://img.shields.io/badge/-VirtualBox-grey.svg">
</div>

## Project Overview

| Feature          | Description                                                                         |
|------------------|-------------------------------------------------------------------------------------|
| File Encryption Software | Designed and implemented file encryption using AES-CBC and SHA-256 for integrity checking.    |
| Multithreading Implementation | Utilized multithreading for encryption and decryption tasks to improve system concurrency and efficiency. |
| Integration and Testing | Developed incrementally with unit and integration testing to ensure seamless OS integration.        |
| Requirement Analysis | Analyzed functional requirements such as encryption, integrity verification, and access prevention. |

## Personal Contributions

> [!IMPORTANT]
> 1. **Design and Implementation of File Encryption Software**: Developed using AES and SHA-256 with C language and OpenSSL library.
> 2. **System-Level Multithreading**: Managed encryption and decryption tasks using multithreading, ensuring synchronization to avoid resource conflicts.
> 3. **Integration and Testing**: Conducted unit and integration testing to verify software stability.
> 4. **Functional and Non-functional Requirements Analysis**: Identified project requirements and provided a user-friendly command-line interface.

## Demo

<div align="left">
  <img src="https://github.com/user-attachments/assets/00cc4c5d-2922-4299-8cfd-1a6ea70b8c51" width="800">
  <img src="https://github.com/user-attachments/assets/4be3387d-3065-46f6-97b3-b6ff09fa9ddc" width="800">
  <img src="https://github.com/user-attachments/assets/8b6325a9-9c7f-4135-b749-729e4bd91a76" width="800">
  <img src="https://github.com/user-attachments/assets/26aa9cb7-4576-468c-ad2c-6338ccd53e2e" width="800">
</div>


## Project Structure

| File | Description |
|------|-------------|
| `code/` | Code files |
| `code/encrypted_and_decrypted_files` | Folder for encrypted files |
| `code/HashValue.bin` | Stores hashed password values |
| `code/adminKey.bin` | Password management |
| `code/dog.jpg, dog.mp4, dog.txt` | Original files in different formats |
| `code/se` | Compiled system files |
| `code/se.c` | System C code |
| `README.md` | Project information and instructions |


## How to Use
> [!NOTE]
> 1. Clone this repository:
>   ```sh
>   git clone https://github.com/DarrylXzq/Secure-OS.git
>   ```
> 2. Configure your Minix OS and VirtualBox environment.
> 3. Compile and run the project using:
>   ```sh
>   make se.c
>   ```
> 4. Use the command-line interface for file encryption operations.

##  Usage Restrictions
> [!WARNING]
> 1. This project and its code may `not` be used for any form of `commercial sales or services`.
> 2. The project must `not` be used as or embedded in any `commercial product`.


## 😄 Acknowledgements

 - Thanks to the family, supervisors, and friends for their help.👋👋👋
 - [github-readme-stats](https://github.com/anuraghazra/github-readme-stats/blob/master/readme.md)
 - [Awesome Readme Templates](https://awesomeopensource.com/project/elangosundar/awesome-README-templates)
 - [Awesome README](https://github.com/matiassingers/awesome-readme)
 - [How to write a Good readme](https://bulldogjob.com/news/449-how-to-write-a-good-readme-for-your-github-project)


## 👋 Feedback

If you have any feedback, please reach out to us at `xiangzq.darryl@gmail.com`

