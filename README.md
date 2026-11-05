# 🛡️ RansomGuard

**RansomGuard** is a lightweight, defensive ransomware early-warning agent designed specifically for Small and Medium Enterprises (MSMEs). It detects ransomware-like behavior in real-time, halts the malicious process, and restores files from clean snapshots.

Built for **CTBF-CS-05 (Ransomware Early-Warning Agent for Small Businesses)** at the **CT BuildFest 2.0 Hackathon** by **Team Onion Syndicate**.

## 🚨 The Problem
Small businesses (clinics, CA offices, local shops) often lack dedicated IT staff and cannot afford enterprise Endpoint Detection and Response (EDR) tools. A single ransomware infection can lock all their critical records (invoices, client data) and halt operations.

## ✨ Key Features
- **Canary Tripwires**: Plants hidden canary files in protected folders. If ransomware attempts to encrypt them, an instant alert is triggered.
- **Multi-Signal Detection**: Detects mass file renames, rapid modifications, and entropy spikes (encrypted data).
- **Real-time Threat Meter**: A live dashboard showing current threat levels and live file activity.
- **Auto-Stop**: Identifies the malicious process using `psutil` and immediately terminates it before it can encrypt everything.
- **One-Click Restore**: Restores affected files from clean snapshots and removes the corrupted `.locked` files, verified by SHA-256 hashes.

## 🛠️ Tech Stack
- **Frontend**: HTML, CSS, Vanilla JavaScript
- **Backend**: Python, Flask
- **Database**: SQLite (Local, secure)
- **Security & Monitoring**: `watchdog` (file system events), `psutil` (process management)

## 👥 Team Onion Syndicate
- **Udhay Karan Singh** (Team Leader) - Project Lead & Backend Logic
- **Sushant** - Business Strategy & Market Research
- **Aryan** - System Architecture & Core Development
- **Vishav Dev Singh** - Backend & Detection Engine
- **Anshuman** - Frontend & Dashboard Integration

## 🚀 How to Run Locally

1. **Clone the repository:**
   ```bash
   git clone https://github.com/mann512/RansomGuard.git
   cd RansomGuard
