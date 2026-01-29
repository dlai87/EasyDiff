# EasyDiff - MaxDiff Survey Application

A production-ready MaxDiff (Best-Worst Scaling) survey application with modern Scandinavian minimal design. Create, distribute, and analyze preference surveys with ease.

## Features

- **Create Studies**: Build MaxDiff surveys with customizable items and settings
- **Share & Collect**: Generate unique survey links for respondents
- **Analyze Results**: View preference rankings, tornado charts, and export data to CSV
- **Mobile-Friendly**: Responsive design works on all devices
- **User Authentication**: Secure login with email/password

## Tech Stack

- **Backend**: Python 3.10+ with Flask
- **Database**: SQLite with SQLAlchemy ORM
- **Frontend**: HTML, CSS, vanilla JavaScript
- **Auth**: Flask-Login with password hashing
- **Styling**: Custom CSS with Scandinavian design tokens

## Quick Start

### Prerequisites

- Python 3.10 or higher
- pip (Python package manager)

### Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd EasyDiff
   ```

2. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Set up environment variables (optional):
   ```bash
   cp .env.example .env
   # Edit .env to set SECRET_KEY for production
   ```

5. Run the application:
   ```bash
   python app.py
   ```

6. Open your browser to `http://localhost:5000`

## Usage

### Creating a Study

1. Register or log in to your account
2. Click "New Study" from the dashboard
3. Add a name and description for your study
4. Add at least 4 items to compare
5. Configure settings (items per question, number of questions)
6. Click "Publish" to make the study active

### Collecting Responses

1. Copy the share link from an active study
2. Send the link to your respondents
3. Respondents select their best and worst options for each question
4. View results in real-time as responses come in

### Analyzing Results

- **Preference Ranking**: Items ordered by normalized score (0-100)
- **Tornado Chart**: Visual comparison of Best vs Worst selections
- **Detailed Scores**: Raw counts and calculations
- **CSV Export**: Download data for further analysis

## MaxDiff Methodology

EasyDiff uses **Best-Worst Counting** for scoring:

```
Score = (Times chosen Best) - (Times chosen Worst)
```

Scores are normalized to a 0-100 scale for easy interpretation.

### Balanced Design

The survey uses a greedy algorithm to create balanced sets where:
- Each item appears approximately equally across all questions
- Item pairings are varied to minimize co-occurrence bias
- Sets are randomized within balance constraints

## Project Structure

```
EasyDiff/
├── app.py              # Main Flask application and routes
├── config.py           # Configuration settings
├── models.py           # SQLAlchemy database models
├── maxdiff.py          # BIBD generation and scoring logic
├── requirements.txt    # Python dependencies
├── static/
│   ├── css/
│   │   └── style.css   # Scandinavian-style CSS
│   └── js/
│       └── main.js     # Frontend JavaScript
└── templates/
    ├── base.html       # Base template with navigation
    ├── index.html      # Landing page
    ├── dashboard.html  # User dashboard
    ├── auth/
    │   ├── login.html
    │   └── register.html
    ├── study/
    │   ├── new.html
    │   ├── edit.html
    │   └── results.html
    └── survey/
        ├── start.html
        ├── question.html
        ├── complete.html
        └── inactive.html
```

## Configuration

Environment variables (can be set in `.env`):

| Variable | Description | Default |
|----------|-------------|---------|
| `SECRET_KEY` | Flask session secret key | `dev-secret-key-change-in-production` |
| `DATABASE_URL` | SQLite database path | `sqlite:///easydiff.db` |
| `GOOGLE_CLIENT_ID` | Google OAuth client ID | (disabled if empty) |
| `GOOGLE_CLIENT_SECRET` | Google OAuth client secret | (disabled if empty) |

### Setting up Google OAuth (Optional)

1. Go to [Google Cloud Console](https://console.cloud.google.com/apis/credentials)
2. Create a new project or select an existing one
3. Go to "Credentials" and click "Create Credentials" > "OAuth client ID"
4. Select "Web application" as the application type
5. Add authorized redirect URI: `http://localhost:5000/authorize/google` (for local development)
6. Copy the Client ID and Client Secret to your `.env` file:
   ```
   GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
   GOOGLE_CLIENT_SECRET=your-client-secret
   ```

Note: For production, add your production domain to the authorized redirect URIs.

## Development

### Running in Debug Mode

```bash
FLASK_DEBUG=1 python app.py
```

### Database

The SQLite database is automatically created on first run. To reset:

```bash
rm instance/easydiff.db
python app.py
```

## License

MIT License
