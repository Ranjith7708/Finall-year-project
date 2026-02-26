# Hosting Deep Forensics on Vercel

This guide provides step-by-step instructions to deploy the Deep Forensics application to Vercel.

## Prerequisites

1.  **Vercel Account**: Sign up at [vercel.com](https://vercel.com).
2.  **MongoDB Atlas**: A hosted MongoDB instance. Since Vercel is stateless, local MongoDB will not work.
    - Create a free cluster at [mongodb.com/atlas](https://www.mongodb.com/cloud/atlas).
    - Get your Connection String (URI).
3.  **Vercel CLI (Optional)**: If you prefer command-line deployment.

## Deployment Steps

### 1. Prepare your environment
Ensure you have a `MONGO_URI` ready. It should look like:
`mongodb+srv://<username>:<password>@cluster0.abcde.mongodb.net/forensics?retryWrites=true&w=majority`

### 2. Connect to Vercel
There are two main ways to deploy:

#### Option A: Via GitHub (Recommended)
1.  Push your code to a GitHub repository.
2.  Go to [Vercel Dashboard](https://vercel.com/dashboard).
3.  Click **Add New...** > **Project**.
4.  Import your GitHub repository.

#### Option B: Via Vercel CLI
1.  Open your terminal in the project folder.
2.  Run `npm i -g vercel` (if not installed).
3.  Run `vercel login`.
4.  Run `vercel` and follow the prompts.

### 3. Configure Environment Variables
During the deployment process (or in the Vercel Project Settings > Environment Variables):
Add the following variable:
- **Key**: `MONGO_URI`
- **Value**: Your MongoDB Atlas connection string.

### 4. Database Initialization
Once deployed, the app will connect to MongoDB. You should run the `init_mongodb.py` script locally *once* while pointing to your Atlas URI to create the admin user:
1.  Update your local `.env` with the Atlas `MONGO_URI`.
2.  Run `python init_mongodb.py`.

## Vercel-Specific Configurations
- **Runtime**: Python 3.10 (configured in `vercel.json`).
- **Entry Point**: `api/index.py`.
- **Writable Folders**: Vercel's filesystem is read-only. The app is already configured to use `/tmp/` for temporary uploads, which is allowed on Vercel.

## Troubleshooting
- **Build Failures**: Check the "Deployments" tab in Vercel for logs. Ensure `requirements.txt` is up to date.
- **Database Connection**: Ensure your MongoDB Atlas IP Access List allows connections from everywhere (`0.0.0.0/0`) during initial setup, as Vercel uses dynamic IPs.
