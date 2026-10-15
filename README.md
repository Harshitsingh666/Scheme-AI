<div align="center">

# 🇮🇳 SchemeAI

### AI-powered discovery for Indian government schemes

Helping citizens and businesses discover relevant schemes, understand eligibility, and navigate public-benefit information with greater clarity.

[![Node.js](https://img.shields.io/badge/Node.js-Backend-339933?logo=node.js&logoColor=white)](https://nodejs.org/)
[![Express](https://img.shields.io/badge/Express.js-API-000000?logo=express&logoColor=white)](https://expressjs.com/)
[![Supabase](https://img.shields.io/badge/Supabase-Database-3FCF8E?logo=supabase&logoColor=white)](https://supabase.com/)
[![Groq](https://img.shields.io/badge/Groq-AI%20Integration-F55036)](https://groq.com/)

**[View Repository](https://github.com/Harshitsingh666/Scheme-AI)**

</div>

---

## 📌 Overview

SchemeAI is an AI-assisted platform intended to make Indian government-scheme information easier to explore and understand. Government benefits can be difficult to navigate when eligibility conditions, required documents, and application guidance are spread across multiple sources.

SchemeAI brings scheme discovery and AI assistance into a single web experience, helping users explore relevant information and make more informed decisions.

> **Important:** AI-generated explanations and eligibility suggestions are informational. Always confirm current rules and application details with the relevant official government department or portal.

## ✨ Features

The repository integrates the following capabilities and services. Exact availability may depend on configuration and the current implementation.

- **AI assistance:** Uses the Groq API to generate AI-powered responses.
- **Scheme discovery:** Supports a user-facing experience for exploring government-scheme information.
- **Document processing:** Includes PDF-processing dependencies for supported document workflows.
- **Image/vision integration:** Includes a vision-capable AI integration for supported image inputs.
- **Backend API:** Uses Node.js and Express to handle server-side operations.
- **Database integration:** Connects to Supabase for data storage and related backend services.
- **Security measures:** Includes security-oriented middleware and input/upload handling.
- **Payment integration:** Includes Razorpay-related backend dependencies for payment workflows.

Do not treat every item as enabled in a production deployment: configure the required services and verify the corresponding workflow before use.

## 🧰 Technology Stack

| Layer | Technology |
|---|---|
| Frontend | HTML, CSS, JavaScript |
| Backend | Node.js |
| Web framework | Express.js |
| Database / backend services | Supabase |
| AI provider | Groq API |
| PDF processing | `pdf-parse` |
| Upload handling | Multer |
| Security middleware | Helmet, `express-rate-limit` and related validation |
| Payments | Razorpay |
| Environment configuration | `dotenv` |

## 🏛️ Architecture

```text
┌───────────────────────────────┐
│            User               │
└───────────────┬───────────────┘
                │
                ▼
┌───────────────────────────────┐
│      Web Interface            │
│      HTML / CSS / JavaScript  │
└───────────────┬───────────────┘
                │ HTTP requests
                ▼
┌───────────────────────────────┐
│       Node.js + Express       │
│       Backend / API routes    │
└───────┬───────────┬───────────┘
        │           │
        ▼           ▼
┌──────────────┐ ┌────────────────┐
│   Supabase   │ │    Groq API    │
│ Data/services│ │ AI responses   │
└──────────────┘ └────────────────┘
        │
        ▼
┌───────────────────────────────┐
│ Razorpay (payment workflows)  │
└───────────────────────────────┘
```

This is a high-level conceptual view. The actual request flow depends on which routes and integrations are enabled in the code and environment.

## 📁 Project Structure

The main files identified for this project include:

```text
Scheme-AI/
├── schemeai_v3_connected.html  # Main web interface
├── server.js                  # Express server and API routes
├── package.json               # Dependencies and npm scripts
├── supabase-schema.sql        # Supabase database schema
├── .env                       # Local secrets; do not commit
└── README.md                  # Project documentation
```

If your local checkout contains additional folders or files, update this tree to reflect the current repository.

## 🚀 Getting Started

### Prerequisites

- [Node.js](https://nodejs.org/) and npm
- A [Supabase](https://supabase.com/) project
- A [Groq API key](https://console.groq.com/)
- Git

A Razorpay account is needed only if you plan to configure and test payment features.

### 1. Clone the repository

```bash
git clone https://github.com/Harshitsingh666/Scheme-AI.git
cd Scheme-AI
```

### 2. Install dependencies

```bash
npm install
```

### 3. Configure environment variables

Create a `.env` file in the project root and add the variables required by `server.js`. A typical configuration may look like this:

```env
PORT=3001

SUPABASE_URL=your_supabase_project_url
SUPABASE_SERVICE_ROLE_KEY=your_supabase_service_role_key

GROQ_API_KEY=your_groq_api_key

ENCRYPTION_KEY=your_64_character_hex_key
HMAC_SECRET=replace_with_a_strong_random_secret

FRONTEND_URL=http://localhost:3001

# Configure only if using Razorpay payment features
RAZORPAY_KEY_ID=your_razorpay_key_id
RAZORPAY_KEY_SECRET=your_razorpay_key_secret
```

**Before running the project:** compare these names with the environment-variable checks in your current `server.js`. Remove unused variables and add any required ones missing from this example. Never publish real credentials.

### 4. Set up Supabase

1. Create a project in the Supabase dashboard.
2. Open the SQL Editor.
3. Review `supabase-schema.sql` and run it against the intended project.
4. Add the project URL and required server-side credentials to `.env`.
5. Verify the schema, permissions, and row-level security policies before storing real user data.

Keep privileged Supabase keys on the server only. Never expose a service-role key in frontend code.

### 5. Run the application

If the scripts in `package.json` are unchanged, start the server with:

```bash
npm start
```

For development, if a `dev` script is defined:

```bash
npm run dev
```

Open the local URL configured by your application (commonly `http://localhost:3001` when `PORT=3001`).

If a command fails, check the `scripts` section of `package.json` and the port configured in `.env`.

## 🔐 Security Best Practices

- Keep `.env` out of version control. Commit an `.env.example` containing placeholders instead.
- Never expose API keys, Supabase service-role credentials, payment secrets, or encryption keys in frontend code.
- Use strong, randomly generated secrets and store production secrets in the hosting provider's secret manager.
- Restrict CORS to trusted origins.
- Validate and limit uploaded file types, sizes, and contents.
- Review authentication, authorization, rate limits, and database policies before deployment.
- Verify payment signatures on the server; never trust a client-side payment-success message alone.
- Avoid logging API keys, personal information, or sensitive document contents.
- If credentials were ever committed, rotate them; deleting them from the latest file alone does not remove them from Git history.

If AES-256-GCM encryption is enabled, use the exact key format expected by the implementation. Losing or changing the encryption key can make existing encrypted data unrecoverable.

## 🧪 Testing and Verification

Before deploying, verify these flows in your own environment:

- [ ] The server starts successfully with the documented configuration.
- [ ] The frontend loads from the expected local URL.
- [ ] Required Supabase tables and permissions are configured.
- [ ] Groq requests succeed and errors are handled safely.
- [ ] Invalid and oversized uploads are rejected.
- [ ] Rate limits and security headers behave as expected.
- [ ] Payment verification is tested in Razorpay test mode, if applicable.
- [ ] No secrets are present in browser code, logs, or committed files.

These are recommended checks, not a claim that automated tests already exist.

## 🗺️ Roadmap Ideas

Possible improvements for future versions:

- [ ] Multilingual scheme explanations.
- [ ] Links to official scheme sources and application portals.
- [ ] Clear eligibility explanations with missing-information prompts.
- [ ] More robust document extraction, including OCR for scanned PDFs.
- [ ] Accessible, mobile-first interface improvements.
- [ ] Automated tests and continuous integration.
- [ ] Production deployment guide and monitoring.

These are ideas for future development, not guaranteed current features.

## 🤝 Contributing

Contributions, bug reports, and suggestions are welcome.

1. Fork the repository.
2. Create a branch for your change:

   ```bash
   git checkout -b feature/your-feature
   ```

3. Make your changes and test them.
4. Commit your work:

   ```bash
   git commit -m "Add: describe your change"
   ```

5. Push the branch and open a Pull Request.

Please do not include credentials, private documents, or personal data in commits or issue reports.

## ⚖️ Disclaimer

SchemeAI is an independent informational project and is not affiliated with or endorsed by the Government of India or any government department. Scheme details, eligibility rules, benefits, and deadlines may change. Users should verify all important information through official sources before applying.

AI output can be incomplete or incorrect and should not be treated as an official eligibility decision or legal advice.

## 📄 License

Please check whether the repository contains a `LICENSE` file. If it does not, add a license before describing the project as open source or granting reuse permissions.

## 👨‍💻 Author

**Harshit Singh**

- GitHub: [@Harshitsingh666](https://github.com/Harshitsingh666)
- Repository: [Scheme-AI](https://github.com/Harshitsingh666/Scheme-AI)

---

<div align="center">

**Built with ❤️ to make government-scheme information easier to understand.**

</div>
