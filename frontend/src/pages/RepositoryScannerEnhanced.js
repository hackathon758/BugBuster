import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import { API } from '../App';
import Navigation from '../components/Navigation';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { Input } from '../components/ui/input';
import { Label } from '../components/ui/label';
import { toast } from 'sonner';
import { Github, Loader2, CheckCircle2, AlertCircle, FileCode, Shield, Zap } from 'lucide-react';
import { Badge } from '../components/ui/badge';
import { useNavigate } from 'react-router-dom';
import { Progress } from '../components/ui/progress';

export default function RepositoryScannerEnhanced({ user }) {
  const navigate = useNavigate();
  const [githubUrl, setGithubUrl] = useState('');
  const [scanning, setScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [currentFile, setCurrentFile] = useState('');
  const [scannedFiles, setScannedFiles] = useState([]);
  const [totalFiles, setTotalFiles] = useState(0);
  const [filesAnalyzed, setFilesAnalyzed] = useState(0);
  const [vulnerabilitiesFound, setVulnerabilitiesFound] = useState(0);
  const [scanResults, setScanResults] = useState(null);
  const [statusMessage, setStatusMessage] = useState('');
  const wsRef = useRef(null);
  const sessionIdRef = useRef(null);

  useEffect(() => {
    return () => {
      // Cleanup WebSocket on unmount
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, []);

  const connectWebSocket = (sessionId) => {
    const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsHost = window.location.hostname;
    const wsPort = window.location.port ? `:${window.location.port}` : '';
    const wsUrl = `${wsProtocol}//${wsHost}${wsPort}/api/ws/scan/${sessionId}`;
    
    const ws = new WebSocket(wsUrl);
    
    ws.onopen = () => {
      console.log('WebSocket connected');
    };
    
    ws.onmessage = (event) => {
      // Ignore non-JSON messages like 'pong' keep-alive responses
      if (event.data === 'pong' || event.data === 'ping') {
        return;
      }
      
      try {
        const data = JSON.parse(event.data);
        handleWebSocketMessage(data);
      } catch (error) {
        console.warn('Received non-JSON WebSocket message:', event.data);
      }
    };
    
    ws.onerror = (error) => {
      console.error('WebSocket error:', error);
    };
    
    ws.onclose = () => {
      console.log('WebSocket closed');
    };
    
    wsRef.current = ws;
    
    // Keep connection alive
    const pingInterval = setInterval(() => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send('ping');
      }
    }, 30000);
    
    ws.addEventListener('close', () => {
      clearInterval(pingInterval);
    });
  };

  const handleWebSocketMessage = (data) => {
    switch (data.type) {
      case 'status':
        setStatusMessage(data.message);
        setScanProgress(data.progress || 0);
        if (data.total_files) {
          setTotalFiles(data.total_files);
        }
        break;
        
      case 'scanning_file':
        setCurrentFile(data.file_path);
        setScanProgress(data.progress || 0);
        setScannedFiles(prev => [...prev, {
          path: data.file_path,
          language: data.language,
          status: 'scanning',
          timestamp: new Date()
        }]);
        break;
        
      case 'file_skipped':
        setScannedFiles(prev => [...prev, {
          path: data.file_path,
          status: 'skipped',
          reason: data.reason,
          timestamp: new Date()
        }]);
        break;
        
      case 'vulnerabilities_found':
        setVulnerabilitiesFound(prev => prev + data.count);
        setScannedFiles(prev => prev.map(file => 
          file.path === data.file_path 
            ? { ...file, status: 'completed', vulnerabilities: data.count }
            : file
        ));
        setFilesAnalyzed(prev => prev + 1);
        break;
        
      case 'file_error':
        setScannedFiles(prev => prev.map(file => 
          file.path === data.file_path 
            ? { ...file, status: 'error', error: data.error }
            : file
        ));
        break;
        
      case 'completed':
        setScanProgress(100);
        setStatusMessage('Scan completed!');
        setScanResults(data);
        setScanning(false);
        toast.success('Repository scan completed successfully!');
        setTimeout(() => {
          navigate(`/repositories/${data.repository_id}`);
        }, 2000);
        break;
        
      case 'error':
        setStatusMessage(data.message);
        setScanning(false);
        toast.error(data.message);
        break;
        
      default:
        break;
    }
  };

  const handleGithubScan = async () => {
    if (!githubUrl.trim()) {
      toast.error('Please enter a GitHub repository URL');
      return;
    }

    const githubPattern = /github\.com\/[\w-]+\/[\w.-]+/;
    if (!githubPattern.test(githubUrl)) {
      toast.error('Please enter a valid GitHub URL');
      return;
    }

    setScanning(true);
    setScanProgress(0);
    setScannedFiles([]);
    setFilesAnalyzed(0);
    setVulnerabilitiesFound(0);
    setStatusMessage('Initializing scan...');
    setScanResults(null);

    try {
      const response = await axios.post(`${API}/repositories/scan-github-ws`, {
        github_url: githubUrl
      });
      
      sessionIdRef.current = response.data.session_id;
      connectWebSocket(response.data.session_id);
      
    } catch (error) {
      setScanning(false);
      toast.error(error.response?.data?.detail || 'Failed to start scan');
    }
  };

  const getFileStatusIcon = (status) => {
    switch (status) {
      case 'scanning':
        return <Loader2 className="w-4 h-4 animate-spin text-blue-600" />;
      case 'completed':
        return <CheckCircle2 className="w-4 h-4 text-green-600" />;
      case 'skipped':
        return <AlertCircle className="w-4 h-4 text-gray-400" />;
      case 'error':
        return <AlertCircle className="w-4 h-4 text-red-600" />;
      default:
        return <FileCode className="w-4 h-4 text-gray-400" />;
    }
  };

  const getScoreColor = (score) => {
    if (score >= 80) return 'text-green-600';
    if (score >= 60) return 'text-yellow-600';
    if (score >= 40) return 'text-orange-600';
    return 'text-red-600';
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-blue-50">
      <Navigation user={user} />
      
      <div className="max-w-7xl mx-auto p-6 lg:p-8">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-4xl font-bold text-gray-900 mb-2" style={{ fontFamily: 'Space Grotesk, sans-serif' }}>
            AI-Powered Repository Scanner
          </h1>
          <p className="text-gray-600">Scan GitHub repositories for security vulnerabilities with real-time AI analysis</p>
        </div>

        {!scanning && !scanResults ? (
          /* Scan Input */
          <div className="max-w-4xl mx-auto">
            <Card className="bg-white/80 backdrop-blur-sm border-gray-200 shadow-xl">
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
                    onKeyPress={(e) => e.key === 'Enter' && handleGithubScan()}
                  />
                  <p className="text-xs text-gray-500 mt-2">
                    Example: https://github.com/facebook/react
                  </p>
                </div>

                <div className="bg-gradient-to-r from-blue-50 to-teal-50 border border-blue-200 rounded-lg p-4">
                  <div className="flex items-start gap-3">
                    <Zap className="w-5 h-5 text-blue-600 mt-0.5" />
                    <div className="space-y-2 text-sm text-gray-700">
                      <p className="font-semibold text-blue-900">Advanced Features:</p>
                      <ul className="space-y-1 ml-4">
                        <li>✓ Real-time scanning progress with file-by-file updates</li>
                        <li>✓ Gemini AI-powered vulnerability detection</li>
                        <li>✓ AI-generated fixes for detected vulnerabilities</li>
                        <li>✓ Comprehensive security scoring</li>
                        <li>✓ Download fixed code files</li>
                      </ul>
                    </div>
                  </div>
                </div>

                <Button
                  onClick={handleGithubScan}
                  disabled={!githubUrl.trim()}
                  className="w-full h-12 bg-gradient-to-r from-blue-600 to-teal-500 hover:from-blue-700 hover:to-teal-600 text-white font-semibold"
                >
                  <Github className="w-5 h-5 mr-2" />
                  Start Security Scan
                </Button>
              </CardContent>
            </Card>
          </div>
        ) : scanning ? (
          /* Scanning Progress */
          <div className="space-y-6">
            {/* Progress Overview */}
            <Card className="bg-white/80 backdrop-blur-sm border-gray-200 shadow-xl">
              <CardHeader>
                <CardTitle className="flex items-center gap-2" style={{ fontFamily: 'Space Grotesk, sans-serif' }}>
                  <Loader2 className="w-6 h-6 animate-spin text-blue-600" />
                  Scanning in Progress
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-6">
                {/* Status Message */}
                <div className="text-center">
                  <p className="text-lg font-medium text-gray-700">{statusMessage}</p>
                  {currentFile && (
                    <p className="text-sm text-gray-500 mt-2">
                      Currently analyzing: <span className="font-mono text-blue-600">{currentFile}</span>
                    </p>
                  )}
                </div>

                {/* Progress Bar */}
                <div className="space-y-2">
                  <div className="flex justify-between text-sm text-gray-600">
                    <span>Progress</span>
                    <span className="font-semibold">{scanProgress}%</span>
                  </div>
                  <Progress value={scanProgress} className="h-3" />
                </div>

                {/* Stats Grid */}
                <div className="grid grid-cols-3 gap-4">
                  <div className="text-center p-4 bg-gradient-to-br from-blue-50 to-indigo-50 rounded-xl">
                    <div className="text-3xl font-bold text-blue-600">{totalFiles}</div>
                    <p className="text-sm text-gray-600 mt-1">Total Files</p>
                  </div>
                  <div className="text-center p-4 bg-gradient-to-br from-green-50 to-emerald-50 rounded-xl">
                    <div className="text-3xl font-bold text-green-600">{filesAnalyzed}</div>
                    <p className="text-sm text-gray-600 mt-1">Analyzed</p>
                  </div>
                  <div className="text-center p-4 bg-gradient-to-br from-orange-50 to-red-50 rounded-xl">
                    <div className="text-3xl font-bold text-orange-600">{vulnerabilitiesFound}</div>
                    <p className="text-sm text-gray-600 mt-1">Vulnerabilities</p>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* File List */}
            {scannedFiles.length > 0 && (
              <Card className="bg-white/80 backdrop-blur-sm border-gray-200">
                <CardHeader>
                  <CardTitle style={{ fontFamily: 'Space Grotesk, sans-serif' }}>
                    Files Being Scanned
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2 max-h-[400px] overflow-y-auto">
                    {scannedFiles.slice().reverse().map((file, index) => (
                      <div
                        key={index}
                        className={`flex items-center justify-between p-3 rounded-lg border transition-all duration-300 ${
                          file.status === 'scanning' 
                            ? 'bg-blue-50 border-blue-200 animate-pulse' 
                            : file.status === 'completed'
                            ? 'bg-green-50 border-green-200'
                            : file.status === 'error'
                            ? 'bg-red-50 border-red-200'
                            : 'bg-gray-50 border-gray-200'
                        }`}
                      >
                        <div className="flex items-center gap-3 flex-1 min-w-0">
                          {getFileStatusIcon(file.status)}
                          <div className="flex-1 min-w-0">
                            <p className="font-mono text-sm text-gray-900 truncate">{file.path}</p>
                            {file.language && (
                              <p className="text-xs text-gray-500 capitalize">{file.language}</p>
                            )}
                            {file.reason && (
                              <p className="text-xs text-gray-500">{file.reason}</p>
                            )}
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          {file.vulnerabilities > 0 && (
                            <Badge variant="destructive" className="text-xs">
                              {file.vulnerabilities} issues
                            </Badge>
                          )}
                          {file.status === 'completed' && !file.vulnerabilities && (
                            <Badge variant="outline" className="text-xs bg-green-50 text-green-700 border-green-200">
                              Clean
                            </Badge>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            )}
          </div>
        ) : scanResults ? (
          /* Scan Results */
          <div className="space-y-6">
            <Card className="bg-white/80 backdrop-blur-sm border-gray-200 shadow-xl">
              <CardHeader>
                <CardTitle className="flex items-center gap-2" style={{ fontFamily: 'Space Grotesk, sans-serif' }}>
                  <CheckCircle2 className="w-6 h-6 text-green-600" />
                  Scan Completed Successfully
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
                  <div className="text-center p-6 bg-gradient-to-br from-blue-50 to-teal-50 rounded-xl">
                    <Shield className="w-8 h-8 mx-auto mb-2 text-blue-600" />
                    <div className={`text-5xl font-bold ${getScoreColor(scanResults.security_score)}`}>
                      {scanResults.security_score}
                    </div>
                    <p className="text-sm text-gray-600 mt-2 font-medium">Security Score</p>
                  </div>

                  <div className="text-center p-6 bg-gradient-to-br from-purple-50 to-pink-50 rounded-xl">
                    <FileCode className="w-8 h-8 mx-auto mb-2 text-purple-600" />
                    <div className="text-5xl font-bold text-gray-900">
                      {scanResults.files_analyzed}
                    </div>
                    <p className="text-sm text-gray-600 mt-2 font-medium">Files Analyzed</p>
                  </div>

                  <div className="text-center p-6 bg-gradient-to-br from-orange-50 to-yellow-50 rounded-xl">
                    <AlertCircle className="w-8 h-8 mx-auto mb-2 text-orange-600" />
                    <div className="text-5xl font-bold text-gray-900">
                      {scanResults.total_vulnerabilities}
                    </div>
                    <p className="text-sm text-gray-600 mt-2 font-medium">Total Issues</p>
                  </div>
                </div>

                <div className="flex gap-4">
                  <Button 
                    onClick={() => navigate(`/repositories/${scanResults.repository_id}`)} 
                    className="flex-1 bg-gradient-to-r from-blue-600 to-teal-500"
                  >
                    View Detailed Report
                  </Button>
                  <Button 
                    onClick={() => {
                      setScanResults(null);
                      setScannedFiles([]);
                      setGithubUrl('');
                    }} 
                    variant="outline" 
                    className="flex-1"
                  >
                    Scan Another Repository
                  </Button>
                </div>
              </CardContent>
            </Card>
          </div>
        ) : null}
      </div>
    </div>
  );
}
