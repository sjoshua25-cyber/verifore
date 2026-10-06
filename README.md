# VERIFORE — Forensic Bloodstain Pattern Analysis (BPA) Platform

Digital Evidence Submission and Forensic Bloodstain Pattern Analysis Platform with PDF reporting, angle calculation, and analyst evaluation workflows.

## Technology Stack
- **Frontend**: Vanilla HTML5, CSS3, JavaScript (responsive UI with PDF export via html2pdf & jsPDF).
- **Backend**: Node.js & Express.
- **Database**: SQLite (`better-sqlite3`).
- **Authentication**: `express-session` & `bcryptjs`.

## Setup & Run
```bash
npm install
npm run start
```
The server will run at `http://localhost:3000` (or `http://localhost:3001` if port 3000 is occupied).

## Default Accounts
- **Analyst / Admin**: `admin` / `Admin@123`
- **Superadmin**: `superadmin` / `admin123`
- **Investigator / User**: `demo_user` / `Demo@123`

## Features
- **Geometric Impact Angle Calculations**: $\theta = \arcsin(\text{Width} / \text{Length})$.
- **Bloodstain Pattern Classification**: Passive, Transfer, Cast-Off, Projected, Arterial, Expirated, Drip Trail, etc.
- **Evidence Management**: Image upload with scaling and categorization.
- **Expert Analysis Workflow**: Directionality, 2D Point of Convergence, 3D Area of Origin, and Reconstruction notes.
- **Official BPA Forensic Report**: In-browser viewing and instant client-side PDF downloads.
- **Audit Logging**: Traceable action trail for chain-of-custody compliance.
