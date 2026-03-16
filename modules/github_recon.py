import os
import shutil
import tempfile
import gc
import re
import json 
import requests
from git import Repo
from urllib.parse import urlparse

class GitHubRecon:
    def __init__(self, repo_url, github_token=None, logger_callback=None):
        self.repo_url = repo_url.rstrip('/')
        self.token = github_token
        self.log = logger_callback if logger_callback else print
        self.clone_dir = None
        self.repo = None
        
        try:
            path_parts = urlparse(self.repo_url).path.strip('/').split('/')
            self.owner = path_parts[0]
            self.repo_name = path_parts[1]
        except Exception:
            self.log("❌ [GITHUB] Invalid URL format.")
            self.owner = None

    def clone_repository(self):
        if not self.owner: return False
        
        self.clone_dir = tempfile.mkdtemp(prefix=f"chimera_{self.repo_name}_")
        self.log(f"📥 [GITHUB] Cloning repository {self.owner}/{self.repo_name} locally...")
        
        try:
            clone_url = self.repo_url
            if self.token:
                clone_url = clone_url.replace("https://", f"https://{self.token}@")
            
            self.repo = Repo.clone_from(clone_url, self.clone_dir)
            
            commits = list(self.repo.iter_commits())
            self.log(f"   └── ✅ Repository Cloned Successfully.")
            self.log(f"   └── Total Commits History: {len(commits)}")
            self.log(f"   └── Active Branch: {self.repo.active_branch.name}")
            return True
            
        except Exception as e:
            self.log(f"❌ [GITHUB] Failed to clone repository. {str(e)}")
            self.cleanup()
            return False

    # ==========================================
    # 🔥 PHASE 7: TECH STACK FINGERPRINTING
    # ==========================================
    def detect_tech_stack(self):
        self.log("🧬 [FINGERPRINT] Analyzing repository for Tech Stack & Infrastructure...")
        
        stack = {
            "Frontend": set(),
            "Backend": set(),
            "Database": set(),
            "Infrastructure": set()
        }

        if not self.clone_dir: return stack

        for root, dirs, files in os.walk(self.clone_dir):
            if '.git' in root or 'node_modules' in root or 'venv' in root:
                continue

            # 1. Check Infrastructure Files
            if 'Dockerfile' in files or 'docker-compose.yml' in files: stack["Infrastructure"].add("Docker")
            if 'vercel.json' in files: stack["Infrastructure"].add("Vercel")
            if 'netlify.toml' in files: stack["Infrastructure"].add("Netlify")
            if '.github' in dirs: stack["Infrastructure"].add("GitHub Actions (CI/CD)")
            if 'serverless.yml' in files: stack["Infrastructure"].add("AWS Serverless")

            # 2. Parse package.json (JavaScript/TypeScript Ecosystem)
            if 'package.json' in files:
                try:
                    with open(os.path.join(root, 'package.json'), 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        deps = list(data.get('dependencies', {}).keys()) + list(data.get('devDependencies', {}).keys())
                        
                        # Frontend
                        if 'react' in deps: stack["Frontend"].add("React")
                        if 'vue' in deps: stack["Frontend"].add("Vue.js")
                        if 'next' in deps: stack["Frontend"].add("Next.js")
                        if 'tailwindcss' in deps: stack["Frontend"].add("Tailwind CSS")
                        if 'angular' in deps or '@angular/core' in deps: stack["Frontend"].add("Angular")
                        
                        # Backend
                        if 'express' in deps: stack["Backend"].add("Node.js (Express)")
                        if 'nestjs' in deps or '@nestjs/core' in deps: stack["Backend"].add("Node.js (NestJS)")
                        if 'socket.io' in deps: stack["Backend"].add("WebSockets")
                        
                        # Database
                        if 'mongoose' in deps or 'mongodb' in deps: stack["Database"].add("MongoDB")
                        if 'pg' in deps or 'sequelize' in deps or 'typeorm' in deps: stack["Database"].add("PostgreSQL/SQL")
                        if 'redis' in deps: stack["Database"].add("Redis")
                        if 'firebase' in deps or 'firebase-admin' in deps: stack["Database"].add("Firebase")
                except Exception: pass

            # 3. Parse requirements.txt (Python Ecosystem)
            if 'requirements.txt' in files:
                try:
                    with open(os.path.join(root, 'requirements.txt'), 'r', encoding='utf-8') as f:
                        content = f.read().lower()
                        if 'django' in content: stack["Backend"].add("Python (Django)")
                        if 'flask' in content: stack["Backend"].add("Python (Flask)")
                        if 'fastapi' in content: stack["Backend"].add("Python (FastAPI)")
                        if 'psycopg2' in content or 'sqlalchemy' in content: stack["Database"].add("PostgreSQL/SQL")
                        if 'pymongo' in content: stack["Database"].add("MongoDB")
                        if 'boto3' in content: stack["Infrastructure"].add("AWS")
                except Exception: pass

            # 4. Check for Go, Java, PHP, etc.
            if 'go.mod' in files: stack["Backend"].add("Go (Golang)")
            if 'pom.xml' in files or 'build.gradle' in files: stack["Backend"].add("Java (Spring/Maven)")
            if 'composer.json' in files: stack["Backend"].add("PHP (Laravel/Symfony)")

        # Convert sets to lists for clean output
        for key in stack:
            stack[key] = list(stack[key])
            if stack[key]:
                self.log(f"   └── {key}: {', '.join(stack[key])}")
                
        if all(len(v) == 0 for v in stack.values()):
            self.log("   └── ⚠️ Could not definitively identify the tech stack.")

        return stack

    def scan_codebase(self):
        if not self.clone_dir: return []
        self.log("📂 [GITHUB] Mapping local file structure...")
        
        target_extensions = [
    '.py', '.js', '.ts', '.jsx', '.tsx', '.php', '.go', '.java', '.c', '.cpp', '.rb',
    '.sql', '.env', '.yml', '.yaml', '.xml', '.json', '.html', '.css', '.md', '.sh', '.dockerfile'
]
        scannable_files = []
        
        for root, dirs, files in os.walk(self.clone_dir):
            if '.git' in root or 'node_modules' in root or 'vendor' in root or 'venv' in root:
                continue
                
            for file in files:
                ext = os.path.splitext(file)[1]
                path = os.path.join(root, file)
                
                is_valid_ext = ext in target_extensions
                is_not_test = 'test' not in file.lower() and 'spec' not in file.lower()
                is_not_lock = 'lock' not in file.lower() and 'config' not in file.lower()
                
                if is_valid_ext and is_not_test and is_not_lock:
                    rel_path = os.path.relpath(path, self.clone_dir)
                    scannable_files.append((path, rel_path))
        
        self.log(f"   └── Identified {len(scannable_files)} core source files for SAST Audit.")
        return scannable_files

    def get_file_content(self, absolute_path):
        try:
            with open(absolute_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception as e:
            return None

    def scan_secrets(self, files_to_scan):
        self.log("🕵️ [FORENSICS] Scanning local files for hardcoded secrets...")
        secrets_found = []
        patterns = {
            'AWS Access Key': r'(?i)AKIA[0-9A-Z]{16}',
            'Google API Key': r'AIza[0-9A-Za-z\-_]{35}',
            'Stripe Key': r'sk_live_[0-9a-zA-Z]{24}',
            'MongoDB URI': r'mongodb(?:\+srv)?:\/\/[^\s]+',
            'RSA Private Key': r'-----BEGIN (?:RSA|OPENSSH|PRIVATE) KEY-----',
            'Generic Secret': r'(?i)(password|secret|api_key|token|jwt_secret)\s*[:=]\s*[\'"][a-zA-Z0-9\-_]{8,}[\'"]'
        }
        for abs_path, rel_path in files_to_scan:
            content = self.get_file_content(abs_path)
            if not content: continue
            lines = content.split('\n')
            for i, line in enumerate(lines):
                for secret_type, pattern in patterns.items():
                    if re.search(pattern, line):
                        self.log(f"   🚨 LEAK DETECTED: {secret_type} in {rel_path} (Line {i+1})")
                        secrets_found.append({
                            'type': secret_type,
                            'file': rel_path,
                            'line': i + 1,
                            'snippet': line.strip()[:60] + "..." 
                        })
        if not secrets_found:
            self.log("   └── ✅ No hardcoded secrets detected by regex scanner.")
        return secrets_found

    def scan_commits(self):
        self.log("🕰️ [FORENSICS] Analyzing Git commit history for suspicious activity...")
        suspicious_commits = []
        red_flags = ['password', 'secret', 'token', 'credential', 'api key', 'api_key', 'leak', 'remove key', 'hide', 'oops']
        try:
            for commit in list(self.repo.iter_commits())[:100]:
                msg = commit.message.lower()
                for flag in red_flags:
                    if flag in msg:
                        self.log(f"   🚩 SUSPICIOUS COMMIT: [{commit.hexsha[:7]}] {commit.message.strip()}")
                        suspicious_commits.append({
                            'hash': commit.hexsha,
                            'message': commit.message.strip(),
                            'author': commit.author.name
                        })
                        break 
            if not suspicious_commits:
                self.log("   └── ✅ Commit history looks clean.")
        except Exception:
            pass
        return suspicious_commits

    def scan_dependencies(self):
        self.log("📦 [SCA] Cross-referencing dependencies with OSV Vulnerability Database...")
        vuln_deps = []
        for root, dirs, files in os.walk(self.clone_dir):
            if '.git' in root or 'node_modules' in root or 'vendor' in root or 'venv' in root: continue
            if 'package.json' in files:
                pkg_path = os.path.join(root, 'package.json')
                rel_path = os.path.relpath(pkg_path, self.clone_dir)
                try:
                    with open(pkg_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        deps = {**data.get('dependencies', {}), **data.get('devDependencies', {})}
                        queries, pkg_map = [], []
                        for pkg, ver in deps.items():
                            clean_ver = re.sub(r'^[\^~<>=]+', '', ver).strip()
                            queries.append({"version": clean_ver, "package": {"name": pkg, "ecosystem": "npm"}})
                            pkg_map.append((pkg, clean_ver))
                        if queries:
                            res = requests.post("https://api.osv.dev/v1/querybatch", json={"queries": queries})
                            if res.status_code == 200:
                                results = res.json().get('results', [])
                                for i, result in enumerate(results):
                                    if 'vulns' in result:
                                        pkg, clean_ver = pkg_map[i]
                                        vulns = result['vulns']
                                        cves = [v.get('aliases', [''])[0] for v in vulns if v.get('aliases')]
                                        cves = [c for c in cves if c]
                                        self.log(f"   🚨 DEPENDENCY ALERT: {pkg}@{clean_ver} is vulnerable! ({len(vulns)} CVEs)")
                                        vuln_deps.append({
                                            'package': pkg, 'version': clean_ver, 'file': rel_path,
                                            'ecosystem': 'npm', 'cves': ", ".join(cves[:3]) + ("..." if len(cves)>3 else "")
                                        })
                except Exception: pass
            if 'requirements.txt' in files:
                req_path = os.path.join(root, 'requirements.txt')
                rel_path = os.path.relpath(req_path, self.clone_dir)
                try:
                    with open(req_path, 'r', encoding='utf-8') as f:
                        queries, pkg_map = [], []
                        for line in f:
                            line = line.strip()
                            if '==' in line and not line.startswith('#'):
                                parts = line.split('==')
                                pkg, ver = parts[0].strip(), parts[1].split(';')[0].strip() 
                                queries.append({"version": ver, "package": {"name": pkg, "ecosystem": "PyPI"}})
                                pkg_map.append((pkg, ver))
                        if queries:
                            res = requests.post("https://api.osv.dev/v1/querybatch", json={"queries": queries})
                            if res.status_code == 200:
                                results = res.json().get('results', [])
                                for i, result in enumerate(results):
                                    if 'vulns' in result:
                                        pkg, ver = pkg_map[i]
                                        vulns = result['vulns']
                                        cves = [v.get('aliases', [''])[0] for v in vulns if v.get('aliases')]
                                        cves = [c for c in cves if c]
                                        self.log(f"   🚨 DEPENDENCY ALERT: {pkg}@{ver} is vulnerable! ({len(vulns)} CVEs)")
                                        vuln_deps.append({
                                            'package': pkg, 'version': ver, 'file': rel_path,
                                            'ecosystem': 'PyPI', 'cves': ", ".join(cves[:3]) + ("..." if len(cves)>3 else "")
                                        })
                except Exception: pass
        if not vuln_deps:
            self.log("   └── ✅ All dependencies look secure (No known CVEs).")
        return vuln_deps

    def scan_sast_patterns(self, files_to_scan):
        self.log("🔎 [SAST] Performing deep static pattern analysis (Pre-AI filtering)...")
        suspicious_files = []
        sast_patterns = {
            'SQL Injection': r'(?i)(SELECT.*FROM|INSERT INTO|UPDATE.*SET|DELETE FROM).*(\$\{.*\W|\+.*req\.)',
            'Command Injection': r'(?i)(exec|spawn|os\.system|subprocess|eval)\s*\(',
            'XSS / DOM Manipulation': r'(?i)(innerHTML|document\.write|dangerouslySetInnerHTML)',
            'Insecure Deserialization': r'(?i)(pickle\.loads|yaml\.load|unserialize)',
            'Path Traversal': r'(?i)(fs\.readFile|open|readfile).*(\.\.|req\.)',
            'Insecure Crypto': r'(?i)(MD5|SHA1|DES|RC4)'
        }
        sensitive_names = ['auth', 'login', 'user', 'controller', 'route', 'api', 'db', 'config', 'middleware']
        for abs_path, rel_path in files_to_scan:
            content = self.get_file_content(abs_path)
            if not content: continue
            is_suspicious = False
            if any(name in rel_path.lower() for name in sensitive_names):
                is_suspicious = True
            if not is_suspicious:
                for pattern_name, pattern in sast_patterns.items():
                    if re.search(pattern, content):
                        self.log(f"   ⚠️ HOTSPOT FOUND: Potential {pattern_name} sink in {rel_path}")
                        is_suspicious = True
                        break
            if is_suspicious:
                suspicious_files.append((abs_path, rel_path))
        self.log(f"   └── Filtered down to {len(suspicious_files)} high-risk files for AI/ML verification.")
        return suspicious_files

    def cleanup(self):
        if self.repo:
            try:
                self.repo.close()
                self.repo = None
            except: pass
        gc.collect() 
        if self.clone_dir and os.path.exists(self.clone_dir):
            self.log(f"🧹 [CLEANUP] Removing local repository copy...")
            def handle_remove_readonly(func, path, exc):
                import stat
                os.chmod(path, stat.S_IWRITE)
                func(path)
            try:
                shutil.rmtree(self.clone_dir, onerror=handle_remove_readonly)
            except Exception: pass