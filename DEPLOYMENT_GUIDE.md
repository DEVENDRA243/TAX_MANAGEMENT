# Tax Management System - Deployment Guide

## Prerequisites
- Node.js and npm installed
- Vercel CLI installed

## Installation Steps

1. **Install Vercel CLI** (if not already installed):
   ```bash
   npm install -g vercel
   ```

2. **Deploy to Vercel**:
   ```bash
   vercel
   ```

3. **Follow the prompts**:
   - Login to your Vercel account (or create one if you don't have it)
   - Set up the project (default settings are usually fine)
   - Deploy!

## Environment Variables (Optional)
For production security, you should set these environment variables in Vercel dashboard:
- `SECRET_KEY`: A random secret key for session encryption

## Database Notes
- The application uses SQLite which is stored in `/tmp/tax_regime.db` on Vercel
- Note that serverless functions have ephemeral storage, so the database will reset on each deployment
- For production use, consider migrating to a persistent database like PostgreSQL

## Testing the Deployment
After deployment, visit the provided URL to test:
1. Register a new user
2. Login with the created credentials
3. Test tax calculation functionality

## Alternative Free Deployment Options

### 1. Railway
```bash
npm install -g @railway/cli
railway login
railway init
railway add
railway deploy
```

### 2. Render
- Connect your GitHub repository
- Select "Web Service"
- Build command: `pip install -r requirements.txt`
- Start command: `python api/index.py`

### 3. PythonAnywhere
- Upload files via web interface or Git
- Configure WSGI file to point to your Flask app
- Set up virtual environment with requirements

## Troubleshooting

### Common Issues:
1. **Database not found**: The SQLite database is created automatically on first run
2. **Static files not loading**: Check if static files are properly copied to api/static
3. **Session issues**: Ensure SECRET_KEY is set in production

### For Persistent Database:
Consider using:
- Railway PostgreSQL (free tier)
- Render PostgreSQL (free tier)
- Supabase (free tier)
- ElephantSQL (free tier)
