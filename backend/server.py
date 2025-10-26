from fastapi import FastAPI, APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict, EmailStr
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime, timezone, timedelta
import jwt
from passlib.hash import bcrypt
from emergentintegrations.llm.chat import LlmChat, UserMessage
import asyncio
import re
import aiohttp

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# JWT Configuration
JWT_SECRET = os.environ.get('JWT_SECRET', 'your-secret-key-change-in-production')
JWT_ALGORITHM = 'HS256'
JWT_EXPIRATION_HOURS = 24

# Security
security = HTTPBearer()

# Create the main app
app = FastAPI(title="BUGBUSTERSX API", version="1.0.0")
api_router = APIRouter(prefix="/api")

# ==================== MODELS ====================

class User(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    email: EmailStr
    name: str
    password_hash: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class UserRegister(BaseModel):
    email: EmailStr
    name: str
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    id: str
    email: str
    name: str
    created_at: datetime

class Repository(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    name: str
    description: Optional[str] = None
    language: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_scan: Optional[datetime] = None
    security_score: Optional[int] = None

class RepositoryCreate(BaseModel):
    name: str
    description: Optional[str] = None
    language: str

class Scan(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    repository_id: str
    user_id: str
    status: str  # 'pending', 'processing', 'completed', 'failed'
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    total_files: Optional[int] = None
    vulnerabilities_count: Optional[int] = None
    security_score: Optional[int] = None

class Vulnerability(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scan_id: str
    severity: str  # 'critical', 'high', 'medium', 'low', 'info'
    title: str
    description: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    remediation: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class CodeAnalysisRequest(BaseModel):
    code: str
    language: str
    file_name: Optional[str] = None

class RepositoryScanRequest(BaseModel):
    repository_id: str
    files: List[Dict[str, Any]]  # [{'path': 'file.py', 'content': '...', 'language': 'python'}]

class GitHubRepoScanRequest(BaseModel):
    github_url: str

# ==================== AUTH HELPERS ====================

def create_jwt_token(user_id: str, email: str) -> str:
    expiration = datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRATION_HOURS)
    payload = {
        'user_id': user_id,
        'email': email,
        'exp': expiration
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_jwt_token(token: str) -> Dict[str, Any]:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
    token = credentials.credentials
    payload = verify_jwt_token(token)
    user = await db.users.find_one({'id': payload['user_id']}, {'_id': 0})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

# ==================== GEMINI INTEGRATION ====================

# Supported code file extensions
CODE_EXTENSIONS = {
    '.py', '.js', '.jsx', '.ts', '.tsx', '.java', '.cpp', '.c', '.h', '.hpp',
    '.go', '.rb', '.php', '.swift', '.kt', '.rs', '.scala', '.sh', '.bash',
    '.html', '.css', '.scss', '.sql', '.xml', '.json', '.yaml', '.yml'
}

def parse_github_url(url: str) -> Dict[str, str]:
    """
    Parse GitHub URL to extract owner and repo name
    Supports formats:
    - https://github.com/owner/repo
    - https://github.com/owner/repo.git
    - github.com/owner/repo
    """
    url = url.strip().rstrip('/')
    
    # Remove .git suffix if present
    if url.endswith('.git'):
        url = url[:-4]
    
    # Extract owner and repo using regex
    patterns = [
        r'github\.com/([^/]+)/([^/]+)',
        r'github\.com/([^/]+)/([^/]+)\.git'
    ]
    
    for pattern in patterns:
        match = re.search(pattern, url)
        if match:
            return {
                'owner': match.group(1),
                'repo': match.group(2)
            }
    
    raise ValueError("Invalid GitHub URL format")

async def fetch_github_repo_contents(owner: str, repo: str, path: str = "") -> List[Dict[str, Any]]:
    """
    Recursively fetch all files from a GitHub repository
    Returns list of files with their content and metadata
    """
    files = []
    api_url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
    
    async with aiohttp.ClientSession() as session:
        headers = {'Accept': 'application/vnd.github.v3+json'}
        
        async with session.get(api_url, headers=headers) as response:
            if response.status != 200:
                raise HTTPException(
                    status_code=400, 
                    detail=f"Failed to fetch repository: {await response.text()}"
                )
            
            contents = await response.json()
            
            for item in contents:
                if item['type'] == 'file':
                    # Check if it's a code file
                    file_ext = '.' + item['name'].split('.')[-1] if '.' in item['name'] else ''
                    if file_ext.lower() in CODE_EXTENSIONS:
                        # Fetch file content
                        async with session.get(item['download_url']) as file_response:
                            if file_response.status == 200:
                                content = await file_response.text()
                                
                                # Determine language from extension
                                language_map = {
                                    '.py': 'python', '.js': 'javascript', '.jsx': 'javascript',
                                    '.ts': 'typescript', '.tsx': 'typescript', '.java': 'java',
                                    '.cpp': 'cpp', '.c': 'c', '.go': 'go', '.rb': 'ruby',
                                    '.php': 'php', '.swift': 'swift', '.kt': 'kotlin',
                                    '.rs': 'rust', '.scala': 'scala', '.sh': 'bash',
                                    '.html': 'html', '.css': 'css', '.sql': 'sql'
                                }
                                
                                files.append({
                                    'path': item['path'],
                                    'content': content,
                                    'language': language_map.get(file_ext.lower(), 'unknown'),
                                    'size': item['size']
                                })
                
                elif item['type'] == 'dir':
                    # Recursively fetch directory contents
                    subfiles = await fetch_github_repo_contents(owner, repo, item['path'])
                    files.extend(subfiles)
    
    return files

async def analyze_code_with_gemini(code: str, language: str) -> List[Dict[str, Any]]:
    """
    Analyze code using Gemini 2.5 Pro for vulnerability detection
    """
    gemini_api_key = os.environ.get('GEMINI_API_KEY')
    if not gemini_api_key:
        raise HTTPException(status_code=500, detail="GEMINI_API_KEY not configured")
    
    try:
        # Initialize Gemini chat
        chat = LlmChat(
            api_key=gemini_api_key,
            session_id=f"scan_{uuid.uuid4()}",
            system_message="""You are an expert security analyst specialized in detecting code vulnerabilities.
            Analyze the provided code and identify security vulnerabilities, bugs, and code quality issues.
            
            For each vulnerability found, provide:
            1. Severity (critical, high, medium, low, info)
            2. Title (concise vulnerability name)
            3. Description (detailed explanation)
            4. Line number (approximate)
            5. CWE ID (if applicable)
            6. OWASP category (if applicable)
            7. Remediation (how to fix)
            
            Return ONLY a valid JSON array of vulnerabilities. Example format:
            [
              {
                "severity": "high",
                "title": "SQL Injection Vulnerability",
                "description": "User input is directly concatenated into SQL query without sanitization.",
                "line_number": 42,
                "cwe_id": "CWE-89",
                "owasp_category": "A03:2021 - Injection",
                "remediation": "Use parameterized queries or prepared statements."
              }
            ]
            
            If no vulnerabilities are found, return an empty array: []
            """
        ).with_model("gemini", "gemini-2.0-flash")
        
        # Create analysis prompt
        prompt = f"""Analyze this {language} code for security vulnerabilities:

```{language}
{code}
```

Return a JSON array of vulnerabilities found."""
        
        user_message = UserMessage(text=prompt)
        response = await chat.send_message(user_message)
        
        # Parse JSON response
        import json
        # Extract JSON from response (handle markdown code blocks)
        response_text = response.strip()
        if '```json' in response_text:
            response_text = response_text.split('```json')[1].split('```')[0].strip()
        elif '```' in response_text:
            response_text = response_text.split('```')[1].split('```')[0].strip()
        
        vulnerabilities = json.loads(response_text)
        return vulnerabilities if isinstance(vulnerabilities, list) else []
        
    except json.JSONDecodeError as e:
        logging.error(f"Failed to parse Gemini response: {e}")
        return []
    except Exception as e:
        logging.error(f"Gemini analysis error: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

# ==================== AUTH ROUTES ====================

@api_router.post("/auth/register", response_model=UserResponse)
async def register(user_data: UserRegister):
    # Check if user exists
    existing_user = await db.users.find_one({'email': user_data.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Hash password
    password_hash = bcrypt.hash(user_data.password)
    
    # Create user
    user = User(
        email=user_data.email,
        name=user_data.name,
        password_hash=password_hash
    )
    
    user_dict = user.model_dump()
    user_dict['created_at'] = user_dict['created_at'].isoformat()
    await db.users.insert_one(user_dict)
    
    return UserResponse(
        id=user.id,
        email=user.email,
        name=user.name,
        created_at=user.created_at
    )

@api_router.post("/auth/login")
async def login(credentials: UserLogin):
    user = await db.users.find_one({'email': credentials.email}, {'_id': 0})
    if not user or not bcrypt.verify(credentials.password, user['password_hash']):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_jwt_token(user['id'], user['email'])
    
    return {
        'token': token,
        'user': UserResponse(
            id=user['id'],
            email=user['email'],
            name=user['name'],
            created_at=datetime.fromisoformat(user['created_at']) if isinstance(user['created_at'], str) else user['created_at']
        )
    }

@api_router.get("/auth/me", response_model=UserResponse)
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
    return UserResponse(
        id=current_user['id'],
        email=current_user['email'],
        name=current_user['name'],
        created_at=datetime.fromisoformat(current_user['created_at']) if isinstance(current_user['created_at'], str) else current_user['created_at']
    )

# ==================== ANALYSIS ROUTES ====================

@api_router.post("/analyze/code")
async def analyze_code(request: CodeAnalysisRequest, current_user: dict = Depends(get_current_user)):
    """Real-time code analysis"""
    vulnerabilities = await analyze_code_with_gemini(request.code, request.language)
    
    # Calculate severity counts
    severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for vuln in vulnerabilities:
        severity = vuln.get('severity', 'info').lower()
        if severity in severity_counts:
            severity_counts[severity] += 1
    
    # Calculate security score (0-100)
    total_vulns = len(vulnerabilities)
    if total_vulns == 0:
        security_score = 100
    else:
        weighted_score = (
            severity_counts['critical'] * 20 +
            severity_counts['high'] * 10 +
            severity_counts['medium'] * 5 +
            severity_counts['low'] * 2 +
            severity_counts['info'] * 1
        )
        security_score = max(0, 100 - weighted_score)
    
    return {
        'vulnerabilities': vulnerabilities,
        'severity_counts': severity_counts,
        'security_score': security_score,
        'total_vulnerabilities': total_vulns
    }

@api_router.post("/analyze/repository")
async def analyze_repository(request: RepositoryScanRequest, current_user: dict = Depends(get_current_user)):
    """Full repository scan"""
    # Create scan record
    scan = Scan(
        repository_id=request.repository_id,
        user_id=current_user['id'],
        status='processing',
        total_files=len(request.files)
    )
    
    scan_dict = scan.model_dump()
    scan_dict['started_at'] = scan_dict['started_at'].isoformat()
    await db.scans.insert_one(scan_dict)
    
    # Analyze each file
    all_vulnerabilities = []
    for file_data in request.files:
        try:
            vulnerabilities = await analyze_code_with_gemini(
                file_data['content'],
                file_data.get('language', 'unknown')
            )
            
            # Store vulnerabilities
            for vuln_data in vulnerabilities:
                vuln = Vulnerability(
                    scan_id=scan.id,
                    severity=vuln_data.get('severity', 'info'),
                    title=vuln_data.get('title', 'Unknown Vulnerability'),
                    description=vuln_data.get('description', ''),
                    file_path=file_data.get('path'),
                    line_number=vuln_data.get('line_number'),
                    code_snippet=file_data.get('content', '')[:200],
                    cwe_id=vuln_data.get('cwe_id'),
                    owasp_category=vuln_data.get('owasp_category'),
                    remediation=vuln_data.get('remediation')
                )
                
                vuln_dict = vuln.model_dump()
                vuln_dict['created_at'] = vuln_dict['created_at'].isoformat()
                await db.vulnerabilities.insert_one(vuln_dict)
                all_vulnerabilities.append(vuln)
        except Exception as e:
            logging.error(f"Error analyzing file {file_data.get('path')}: {e}")
    
    # Calculate security score
    severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for vuln in all_vulnerabilities:
        severity = vuln.severity.lower()
        if severity in severity_counts:
            severity_counts[severity] += 1
    
    total_vulns = len(all_vulnerabilities)
    if total_vulns == 0:
        security_score = 100
    else:
        weighted_score = (
            severity_counts['critical'] * 20 +
            severity_counts['high'] * 10 +
            severity_counts['medium'] * 5 +
            severity_counts['low'] * 2 +
            severity_counts['info'] * 1
        )
        security_score = max(0, 100 - weighted_score)
    
    # Update scan status
    await db.scans.update_one(
        {'id': scan.id},
        {
            '$set': {
                'status': 'completed',
                'completed_at': datetime.now(timezone.utc).isoformat(),
                'vulnerabilities_count': total_vulns,
                'security_score': security_score
            }
        }
    )
    
    # Update repository
    await db.repositories.update_one(
        {'id': request.repository_id},
        {
            '$set': {
                'last_scan': datetime.now(timezone.utc).isoformat(),
                'security_score': security_score
            }
        }
    )
    
    return {
        'scan_id': scan.id,
        'status': 'completed',
        'total_vulnerabilities': total_vulns,
        'severity_counts': severity_counts,
        'security_score': security_score
    }

# ==================== REPOSITORY ROUTES ====================

@api_router.post("/repositories", response_model=Repository)
async def create_repository(repo_data: RepositoryCreate, current_user: dict = Depends(get_current_user)):
    repo = Repository(
        user_id=current_user['id'],
        name=repo_data.name,
        description=repo_data.description,
        language=repo_data.language
    )
    
    repo_dict = repo.model_dump()
    repo_dict['created_at'] = repo_dict['created_at'].isoformat()
    await db.repositories.insert_one(repo_dict)
    
    return repo

@api_router.get("/repositories")
async def get_repositories(current_user: dict = Depends(get_current_user)):
    repos = await db.repositories.find(
        {'user_id': current_user['id']},
        {'_id': 0}
    ).to_list(1000)
    
    for repo in repos:
        if isinstance(repo.get('created_at'), str):
            repo['created_at'] = datetime.fromisoformat(repo['created_at'])
        if isinstance(repo.get('last_scan'), str):
            repo['last_scan'] = datetime.fromisoformat(repo['last_scan'])
    
    return repos

@api_router.get("/repositories/{repo_id}")
async def get_repository(repo_id: str, current_user: dict = Depends(get_current_user)):
    repo = await db.repositories.find_one(
        {'id': repo_id, 'user_id': current_user['id']},
        {'_id': 0}
    )
    
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")
    
    if isinstance(repo.get('created_at'), str):
        repo['created_at'] = datetime.fromisoformat(repo['created_at'])
    if isinstance(repo.get('last_scan'), str):
        repo['last_scan'] = datetime.fromisoformat(repo['last_scan'])
    
    return repo

# ==================== SCAN ROUTES ====================

@api_router.get("/scans")
async def get_scans(current_user: dict = Depends(get_current_user)):
    scans = await db.scans.find(
        {'user_id': current_user['id']},
        {'_id': 0}
    ).sort('started_at', -1).to_list(100)
    
    for scan in scans:
        if isinstance(scan.get('started_at'), str):
            scan['started_at'] = datetime.fromisoformat(scan['started_at'])
        if isinstance(scan.get('completed_at'), str):
            scan['completed_at'] = datetime.fromisoformat(scan['completed_at'])
    
    return scans

@api_router.get("/scans/{scan_id}")
async def get_scan(scan_id: str, current_user: dict = Depends(get_current_user)):
    scan = await db.scans.find_one(
        {'id': scan_id, 'user_id': current_user['id']},
        {'_id': 0}
    )
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if isinstance(scan.get('started_at'), str):
        scan['started_at'] = datetime.fromisoformat(scan['started_at'])
    if isinstance(scan.get('completed_at'), str):
        scan['completed_at'] = datetime.fromisoformat(scan['completed_at'])
    
    return scan

# ==================== VULNERABILITY ROUTES ====================

@api_router.get("/vulnerabilities")
async def get_vulnerabilities(
    scan_id: Optional[str] = None,
    severity: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    # Build query
    query = {}
    if scan_id:
        # Verify scan belongs to user
        scan = await db.scans.find_one({'id': scan_id, 'user_id': current_user['id']})
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        query['scan_id'] = scan_id
    else:
        # Get all scans for user
        user_scans = await db.scans.find({'user_id': current_user['id']}, {'id': 1, '_id': 0}).to_list(1000)
        scan_ids = [s['id'] for s in user_scans]
        query['scan_id'] = {'$in': scan_ids}
    
    if severity:
        query['severity'] = severity
    
    vulnerabilities = await db.vulnerabilities.find(query, {'_id': 0}).to_list(1000)
    
    for vuln in vulnerabilities:
        if isinstance(vuln.get('created_at'), str):
            vuln['created_at'] = datetime.fromisoformat(vuln['created_at'])
    
    return vulnerabilities

@api_router.get("/vulnerabilities/{vuln_id}")
async def get_vulnerability(vuln_id: str, current_user: dict = Depends(get_current_user)):
    vuln = await db.vulnerabilities.find_one({'id': vuln_id}, {'_id': 0})
    
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    
    # Verify access
    scan = await db.scans.find_one({'id': vuln['scan_id'], 'user_id': current_user['id']})
    if not scan:
        raise HTTPException(status_code=403, detail="Access denied")
    
    if isinstance(vuln.get('created_at'), str):
        vuln['created_at'] = datetime.fromisoformat(vuln['created_at'])
    
    return vuln

# ==================== DASHBOARD ROUTES ====================

@api_router.get("/dashboard/overview")
async def get_dashboard_overview(current_user: dict = Depends(get_current_user)):
    # Get repositories count
    repos_count = await db.repositories.count_documents({'user_id': current_user['id']})
    
    # Get scans count
    scans_count = await db.scans.count_documents({'user_id': current_user['id']})
    
    # Get recent scans
    recent_scans = await db.scans.find(
        {'user_id': current_user['id']},
        {'_id': 0}
    ).sort('started_at', -1).limit(5).to_list(5)
    
    # Get vulnerabilities stats
    user_scans = await db.scans.find({'user_id': current_user['id']}, {'id': 1, '_id': 0}).to_list(1000)
    scan_ids = [s['id'] for s in user_scans]
    
    total_vulnerabilities = await db.vulnerabilities.count_documents({'scan_id': {'$in': scan_ids}})
    
    # Get severity breakdown
    severity_pipeline = [
        {'$match': {'scan_id': {'$in': scan_ids}}},
        {'$group': {'_id': '$severity', 'count': {'$sum': 1}}}
    ]
    severity_breakdown = {}
    async for doc in db.vulnerabilities.aggregate(severity_pipeline):
        severity_breakdown[doc['_id']] = doc['count']
    
    # Calculate average security score
    repos_with_scores = await db.repositories.find(
        {'user_id': current_user['id'], 'security_score': {'$exists': True}},
        {'security_score': 1, '_id': 0}
    ).to_list(1000)
    
    avg_security_score = 0
    if repos_with_scores:
        avg_security_score = sum(r['security_score'] for r in repos_with_scores) / len(repos_with_scores)
    
    return {
        'repositories_count': repos_count,
        'scans_count': scans_count,
        'total_vulnerabilities': total_vulnerabilities,
        'severity_breakdown': severity_breakdown,
        'average_security_score': round(avg_security_score, 1),
        'recent_scans': recent_scans
    }

# ==================== TEST ROUTE ====================

@api_router.get("/")
async def root():
    return {"message": "BUGBUSTERSX API v1.0.0", "status": "operational"}

# Include router
app.include_router(api_router)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
