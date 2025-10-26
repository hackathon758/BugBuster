import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { API } from '../App';
import Navigation from '../components/Navigation';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { Input } from '../components/ui/input';
import { Label } from '../components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../components/ui/select';
import { Textarea } from '../components/ui/textarea';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs';
import { toast } from 'sonner';
import { Upload, Shield, Loader2, CheckCircle2, Github } from 'lucide-react';
import { Badge } from '../components/ui/badge';
import { useNavigate } from 'react-router-dom';

export default function RepositoryScanner({ user }) {
  const navigate = useNavigate();
  const [repositories, setRepositories] = useState([]);
  const [selectedRepo, setSelectedRepo] = useState('');
  const [files, setFiles] = useState([{ path: '', content: '', language: 'python' }]);
  const [scanning, setScanning] = useState(false);
  const [results, setResults] = useState(null);
  const [githubUrl, setGithubUrl] = useState('');
  const [scanningGithub, setScanningGithub] = useState(false);

  const languages = [
    { value: 'python', label: 'Python' },
    { value: 'javascript', label: 'JavaScript' },
    { value: 'typescript', label: 'TypeScript' },
    { value: 'java', label: 'Java' },
    { value: 'cpp', label: 'C++' },
    { value: 'go', label: 'Go' },
  ];

  useEffect(() => {
    fetchRepositories();
  }, []);

  const fetchRepositories = async () => {
    try {
      const response = await axios.get(`${API}/repositories`);
      setRepositories(response.data);
      if (response.data.length > 0) {
        setSelectedRepo(response.data[0].id);
      }
    } catch (error) {
      toast.error('Failed to fetch repositories');
    }
  };

  const addFile = () => {
    setFiles([...files, { path: '', content: '', language: 'python' }]);
  };

  const removeFile = (index) => {
    setFiles(files.filter((_, i) => i !== index));
  };

  const updateFile = (index, field, value) => {
    const newFiles = [...files];
    newFiles[index][field] = value;
    setFiles(newFiles);
  };

  const handleScan = async () => {
    if (!selectedRepo) {
      toast.error('Please select a repository');
      return;
    }

    const validFiles = files.filter(f => f.path && f.content);
    if (validFiles.length === 0) {
      toast.error('Please add at least one file to scan');
      return;
    }

    setScanning(true);
    setResults(null);

    try {
      const response = await axios.post(`${API}/analyze/repository`, {
        repository_id: selectedRepo,
        files: validFiles
      });
      setResults(response.data);
      toast.success('Repository scan completed successfully!');
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Scan failed');
    } finally {
      setScanning(false);
    }
  };

  const handleGithubScan = async () => {
    if (!githubUrl.trim()) {
      toast.error('Please enter a GitHub repository URL');
      return;
    }

    // Validate GitHub URL format
    const githubPattern = /github\.com\/[\w-]+\/[\w.-]+/;
    if (!githubPattern.test(githubUrl)) {
      toast.error('Please enter a valid GitHub URL (e.g., https://github.com/owner/repo)');
      return;
    }

    setScanningGithub(true);
    setResults(null);

    try {
      const response = await axios.post(`${API}/repositories/scan-github`, {
        github_url: githubUrl
      });
      setResults(response.data);
      toast.success(`Successfully scanned ${response.data.repository_name}!`);
      fetchRepositories(); // Refresh repository list
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to scan GitHub repository');
    } finally {
      setScanningGithub(false);
    }
  };

  const getScoreColor = (score) => {
    if (score >= 80) return 'text-green-600';
    if (score >= 60) return 'text-yellow-600';
    if (score >= 40) return 'text-orange-600';
    return 'text-red-600';
  };

  const getSeverityColor = (severity) => {
    const colors = {
      critical: 'bg-red-100 text-red-800 border-red-200',
      high: 'bg-orange-100 text-orange-800 border-orange-200',
      medium: 'bg-yellow-100 text-yellow-800 border-yellow-200',
      low: 'bg-blue-100 text-blue-800 border-blue-200',
      info: 'bg-gray-100 text-gray-800 border-gray-200'
    };
    return colors[severity] || colors.info;
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-blue-50">
      <Navigation user={user} />
      
      <div className="max-w-7xl mx-auto p-6 lg:p-8" data-testid="repository-scanner-container">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-4xl font-bold text-gray-900 mb-2" style={{ fontFamily: 'Space Grotesk, sans-serif' }}>
            Repository Scanner
          </h1>
          <p className="text-gray-600">Scan multiple files from your repository for comprehensive security analysis</p>
        </div>

        {results ? (
          /* Scan Results */
          <div className="space-y-6">
            <Card className="bg-white/80 backdrop-blur-sm border-gray-200" data-testid="scan-results-card">
              <CardHeader>
                <CardTitle className="flex items-center gap-2" style={{ fontFamily: 'Space Grotesk, sans-serif' }}>
                  <CheckCircle2 className="w-6 h-6 text-green-600" />
                  Scan Completed
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
                  <div className="text-center p-6 bg-gradient-to-br from-blue-50 to-teal-50 rounded-xl">
                    <div className={`text-5xl font-bold ${getScoreColor(results.security_score)}`}>
                      {results.security_score}
                    </div>
                    <p className="text-sm text-gray-600 mt-2 font-medium">Security Score</p>
                  </div>

                  <div className="text-center p-6 bg-gradient-to-br from-purple-50 to-pink-50 rounded-xl">
                    <div className="text-5xl font-bold text-gray-900">
                      {results.total_vulnerabilities}
                    </div>
                    <p className="text-sm text-gray-600 mt-2 font-medium">Vulnerabilities Found</p>
                  </div>

                  <div className="text-center p-6 bg-gradient-to-br from-orange-50 to-yellow-50 rounded-xl">
                    <div className="text-5xl font-bold text-gray-900">
                      {results.severity_counts?.critical || 0}
                    </div>
                    <p className="text-sm text-gray-600 mt-2 font-medium">Critical Issues</p>
                  </div>
                </div>

                {/* Severity Breakdown */}
                <div className="grid grid-cols-5 gap-3 mb-6">
                  {Object.entries(results.severity_counts || {}).map(([severity, count]) => (
                    <div key={severity} className="text-center">
                      <Badge className={`${getSeverityColor(severity)} capitalize w-full`}>
                        {severity}
                      </Badge>
                      <p className="text-2xl font-bold text-gray-900 mt-2">{count}</p>
                    </div>
                  ))}
                </div>

                <div className="flex gap-4">
                  <Button 
                    onClick={() => navigate('/vulnerabilities')} 
                    className="flex-1 bg-gradient-to-r from-blue-600 to-teal-500"
                    data-testid="view-vulnerabilities-button"
                  >
                    View All Vulnerabilities
                  </Button>
                  <Button 
                    onClick={() => setResults(null)} 
                    variant="outline" 
                    className="flex-1"
                    data-testid="scan-another-button"
                  >
                    Scan Another Repository
                  </Button>
                </div>
              </CardContent>
            </Card>
          </div>
        ) : (
          /* Scan Configuration */
          <Tabs defaultValue="github" className="w-full">
            <TabsList className="grid w-full max-w-md mx-auto grid-cols-2 mb-8">
              <TabsTrigger value="github">
                <Github className="w-4 h-4 mr-2" />
                GitHub URL
              </TabsTrigger>
              <TabsTrigger value="manual">
                <Upload className="w-4 h-4 mr-2" />
                Manual Upload
              </TabsTrigger>
            </TabsList>

            {/* GitHub URL Scan Tab */}
            <TabsContent value="github" className="space-y-6">
              <div className="max-w-4xl mx-auto">
                <Card className="bg-white/80 backdrop-blur-sm border-gray-200">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2" style={{ fontFamily: 'Space Grotesk, sans-serif' }}>
                      <Github className="w-6 h-6" />
                      Scan GitHub Repository
                    </CardTitle>
                    <p className="text-sm text-gray-600 mt-2">
                      Enter a public GitHub repository URL to automatically fetch and scan all code files
                    </p>
                  </CardHeader>
                  <CardContent className="space-y-6">
                    <div>
                      <Label>GitHub Repository URL</Label>
                      <Input
                        value={githubUrl}
                        onChange={(e) => setGithubUrl(e.target.value)}
                        placeholder="https://github.com/owner/repository"
                        className="mt-1.5"
                        data-testid="github-url-input"
                      />
                      <p className="text-xs text-gray-500 mt-2">
                        Example: https://github.com/facebook/react
                      </p>
                    </div>

                    <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                      <div className="flex items-start gap-3">
                        <Shield className="w-5 h-5 text-blue-600 mt-0.5" />
                        <div className="space-y-2 text-sm text-gray-700">
                          <p className="font-semibold text-blue-900">What happens next:</p>
                          <ul className="space-y-1 ml-4">
                            <li>✓ Fetches all code files from the repository</li>
                            <li>✓ Analyzes each file with Gemini AI</li>
                            <li>✓ Detects security vulnerabilities and bugs</li>
                            <li>✓ Generates comprehensive security report</li>
                          </ul>
                          <p className="text-xs text-gray-600 mt-3">
                            <strong>Note:</strong> Large repositories may take a few minutes to scan
                          </p>
                        </div>
                      </div>
                    </div>

                    <Button
                      onClick={handleGithubScan}
                      disabled={scanningGithub || !githubUrl.trim()}
                      className="w-full h-12 bg-gradient-to-r from-blue-600 to-teal-500 hover:from-blue-700 hover:to-teal-600 text-white font-semibold"
                      data-testid="scan-github-button"
                    >
                      {scanningGithub ? (
                        <>
                          <Loader2 className="w-5 h-5 mr-2 animate-spin" />
                          Scanning Repository...
                        </>
                      ) : (
                        <>
                          <Github className="w-5 h-5 mr-2" />
                          Scan GitHub Repository
                        </>
                      )}
                    </Button>
                  </CardContent>
                </Card>
              </div>
            </TabsContent>

            {/* Manual Upload Tab */}
            <TabsContent value="manual">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="lg:col-span-2 space-y-6">
              {/* Repository Selection */}
              <Card className="bg-white/80 backdrop-blur-sm border-gray-200">
                <CardHeader>
                  <CardTitle style={{ fontFamily: 'Space Grotesk, sans-serif' }}>Select Repository</CardTitle>
                </CardHeader>
                <CardContent>
                  {repositories.length > 0 ? (
                    <Select value={selectedRepo} onValueChange={setSelectedRepo}>
                      <SelectTrigger data-testid="repository-select">
                        <SelectValue placeholder="Choose a repository" />
                      </SelectTrigger>
                      <SelectContent>
                        {repositories.map((repo) => (
                          <SelectItem key={repo.id} value={repo.id}>
                            {repo.name} ({repo.language})
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  ) : (
                    <div className="text-center py-6 text-gray-500">
                      <p>No repositories found. Please create one first.</p>
                      <Button onClick={() => navigate('/repositories')} className="mt-4" variant="outline">
                        Go to Repositories
                      </Button>
                    </div>
                  )}
                </CardContent>
              </Card>

              {/* Files to Scan */}
              <Card className="bg-white/80 backdrop-blur-sm border-gray-200">
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <CardTitle style={{ fontFamily: 'Space Grotesk, sans-serif' }}>Files to Scan</CardTitle>
                    <Button size="sm" onClick={addFile} variant="outline" data-testid="add-file-button">
                      <Upload className="w-4 h-4 mr-2" />
                      Add File
                    </Button>
                  </div>
                </CardHeader>
                <CardContent className="space-y-6">
                  {files.map((file, index) => (
                    <div key={index} className="p-4 border border-gray-200 rounded-xl space-y-4 bg-gray-50">
                      <div className="flex items-center justify-between">
                        <h4 className="font-semibold text-gray-700">File {index + 1}</h4>
                        {files.length > 1 && (
                          <Button size="sm" variant="ghost" onClick={() => removeFile(index)} data-testid={`remove-file-${index}`}>
                            Remove
                          </Button>
                        )}
                      </div>

                      <div>
                        <Label>File Path</Label>
                        <Input
                          value={file.path}
                          onChange={(e) => updateFile(index, 'path', e.target.value)}
                          placeholder="src/main.py"
                          className="mt-1.5"
                          data-testid={`file-path-${index}`}
                        />
                      </div>

                      <div>
                        <Label>Language</Label>
                        <Select value={file.language} onValueChange={(value) => updateFile(index, 'language', value)}>
                          <SelectTrigger className="mt-1.5" data-testid={`file-language-${index}`}>
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            {languages.map((lang) => (
                              <SelectItem key={lang.value} value={lang.value}>
                                {lang.label}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      </div>

                      <div>
                        <Label>Code Content</Label>
                        <Textarea
                          value={file.content}
                          onChange={(e) => updateFile(index, 'content', e.target.value)}
                          placeholder="Paste file content here..."
                          className="mt-1.5 min-h-[150px] font-mono text-sm"
                          data-testid={`file-content-${index}`}
                        />
                      </div>
                    </div>
                  ))}
                </CardContent>
              </Card>
            </div>

            {/* Scan Action */}
            <div>
              <Card className="bg-gradient-to-br from-blue-50 to-teal-50 border-blue-200 sticky top-24">
                <CardHeader>
                  <CardTitle style={{ fontFamily: 'Space Grotesk, sans-serif' }}>Ready to Scan</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="flex items-center gap-3 p-4 bg-white rounded-lg">
                    <Shield className="w-8 h-8 text-blue-600" />
                    <div>
                      <p className="font-semibold text-gray-900">AI-Powered Analysis</p>
                      <p className="text-xs text-gray-600">Using Gemini 2.0 Flash</p>
                    </div>
                  </div>

                  <div className="space-y-2 text-sm text-gray-600">
                    <p>✓ Detects OWASP Top 10</p>
                    <p>✓ Identifies CWE vulnerabilities</p>
                    <p>✓ Provides remediation guidance</p>
                    <p>✓ Real-time security scoring</p>
                  </div>

                  <Button
                    onClick={handleScan}
                    disabled={scanning || !selectedRepo}
                    className="w-full h-12 bg-gradient-to-r from-blue-600 to-teal-500 hover:from-blue-700 hover:to-teal-600 text-white font-semibold"
                    data-testid="start-scan-button"
                  >
                    {scanning ? (
                      <>
                        <Loader2 className="w-5 h-5 mr-2 animate-spin" />
                        Scanning Repository...
                      </>
                    ) : (
                      <>
                        <Shield className="w-5 h-5 mr-2" />
                        Start Security Scan
                      </>
                    )}
                  </Button>

                  <p className="text-xs text-gray-500 text-center">
                    Scans typically complete in 30-60 seconds
                  </p>
                </CardContent>
              </Card>
            </div>
          </div>
            </TabsContent>
          </Tabs>
        )}
      </div>
    </div>
  );
}
