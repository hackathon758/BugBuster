import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import { API } from '../App';
import Navigation from '../components/Navigation';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { Input } from '../components/ui/input';
import { Label } from '../components/ui/label';
import { toast } from 'sonner';
import { Github, Loader2, CheckCircle2, AlertCircle, FileCode, Shield, Zap, Lock, Bug, Code, Database, Key, XCircle, Cpu, Network, Eye, Target } from 'lucide-react';
import { Badge } from '../components/ui/badge';
import { useNavigate } from 'react-router-dom';
import { Progress } from '../components/ui/progress';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs';

// Analysis stages for advanced scanning
const ANALYSIS_STAGES = [
  { id: 'initialization', name: 'Initialization', icon: Cpu, description: 'Preparing analysis engine' },
  { id: 'ast_parsing', name: 'AST Parsing', icon: Code, description: 'Building abstract syntax trees' },
  { id: 'ir_generation', name: 'IR Generation', icon: Database, description: 'Creating unified representation' },
  { id: 'taint_analysis', name: 'Taint Analysis', icon: Eye, description: 'Tracking data flows' },
  { id: 'pattern_matching', name: 'Pattern Recognition', icon: Target, description: 'Detecting vulnerability patterns' },
  { id: 'cross_language_analysis', name: 'Cross-Language Analysis', icon: Network, description: 'Analyzing language boundaries' },
  { id: 'storing_results', name: 'Finalizing', icon: CheckCircle2, description: 'Storing results' }
];

export default function AdvancedScanner({ user }) {
  const navigate = useNavigate();
  const [githubUrl, setGithubUrl] = useState('');
  const [scanMode, setScanMode] = useState('advanced'); // 'basic' or 'advanced'
  const [scanning, setScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [currentStage, setCurrentStage] = useState('');
  const [currentFile, setCurrentFile] = useState('');
  const [scannedFiles, setScannedFiles] = useState([]);
  const [totalFiles, setTotalFiles] = useState(0);
  const [filesAnalyzed, setFilesAnalyzed] = useState(0);
  const [vulnerabilitiesFound, setVulnerabilitiesFound] = useState(0);
  const [crossLangVulns, setCrossLangVulns] = useState(0);
  const [scanResults, setScanResults] = useState(null);
  const [statusMessage, setStatusMessage] = useState('');
  const [algorithmsUsed, setAlgorithmsUsed] = useState([]);
  const wsRef = useRef(null);
  const sessionIdRef = useRef(null);

  useEffect(() => {
    return () => {
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
    console.log('WebSocket message:', data);
    
    if (data.status === 'processing') {
      if (data.stage) {
        setCurrentStage(data.stage);
      }
      if (data.message) {
        setStatusMessage(data.message);
      }
      if (data.file_path) {
        setCurrentFile(data.file_path);
        setScannedFiles(prev => [...prev, {
          path: data.file_path,
          language: data.language,
          status: 'completed'
        }]);
      }
      if (data.total_files) {
        setTotalFiles(data.total_files);
      }
      if (data.analyzed !== undefined) {
        setFilesAnalyzed(data.analyzed);
      }
      if (data.progress !== undefined) {
        setScanProgress(data.progress);
      }
      if (data.vulnerabilities_count) {
        setVulnerabilitiesFound(prev => prev + data.vulnerabilities_count);
      }
    } else if (data.status === 'completed') {
      setScanning(false);
      setScanProgress(100);
      setScanResults(data);
      setVulnerabilitiesFound(data.total_vulnerabilities || 0);
      setCrossLangVulns(data.cross_language_vulnerabilities || 0);
      
      if (wsRef.current) {
        wsRef.current.close();
      }
      
      toast.success(`Scan completed! Found ${data.total_vulnerabilities || 0} vulnerabilities`);
      
      setTimeout(() => {
        navigate(`/repositories/${data.repository_id}`);
      }, 2000);
    } else if (data.status === 'error') {
      setScanning(false);
      setStatusMessage(data.message || 'Scan failed');
      toast.error(data.message || 'Scan failed');
      
      if (wsRef.current) {
        wsRef.current.close();
      }
    }
  };

  const handleStartScan = async () => {
    if (!githubUrl.trim()) {
      toast.error('Please enter a GitHub repository URL');
      return;
    }

    const githubUrlPattern = /^https?:\/\/(www\.)?github\.com\/[\w-]+\/[\w.-]+\/?$/;
    if (!githubUrlPattern.test(githubUrl.trim())) {
      toast.error('Please enter a valid GitHub repository URL (e.g., https://github.com/owner/repo)');
      return;
    }

    try {
      setScanning(true);
      setScanProgress(0);
      setStatusMessage('Initializing scan...');
      setScannedFiles([]);
      setFilesAnalyzed(0);
      setVulnerabilitiesFound(0);
      setCrossLangVulns(0);
      setCurrentStage('');
      setAlgorithmsUsed([]);

      const token = localStorage.getItem('token');
      const endpoint = scanMode === 'advanced' 
        ? '/repositories/scan-github-advanced-ws'
        : '/repositories/scan-github-ws';
      
      const response = await axios.post(
        `${API}${endpoint}`,
        { github_url: githubUrl.trim() },
        { headers: { Authorization: `Bearer ${token}` } }
      );

      sessionIdRef.current = response.data.session_id;
      connectWebSocket(response.data.session_id);
      
      toast.success(`${scanMode === 'advanced' ? 'Advanced' : 'Basic'} scan started!`);
    } catch (error) {
      setScanning(false);
      console.error('Error starting scan:', error);
      toast.error(error.response?.data?.detail || 'Failed to start scan');
    }
  };

  const getCurrentStageInfo = () => {
    return ANALYSIS_STAGES.find(s => s.id === currentStage) || null;
  };

  const stageInfo = getCurrentStageInfo();
  const completedStages = ANALYSIS_STAGES.filter((_, idx) => {
    const currentIdx = ANALYSIS_STAGES.findIndex(s => s.id === currentStage);
    return idx < currentIdx;
  });

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900">
      <Navigation user={user} />
      
      <div className="container mx-auto px-4 py-8">
        <div className="max-w-6xl mx-auto">
          {/* Header */}
          <div className="text-center mb-8">
            <div className="inline-flex items-center gap-2 bg-purple-500/20 px-4 py-2 rounded-full mb-4">
              <Zap className="w-5 h-5 text-purple-400" />
              <span className="text-purple-300 font-semibold">Advanced Security Scanner</span>
            </div>
            <h1 className="text-4xl font-bold text-white mb-3">
              Multi-Language Vulnerability Detection
            </h1>
            <p className="text-slate-300 text-lg">
              Powered by AST parsing, taint analysis, and cross-language security detection
            </p>
          </div>

          {/* Scan Mode Selection */}
          <Card className="bg-slate-800/50 border-slate-700 backdrop-blur-sm mb-6">
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <Shield className="w-5 h-5 text-purple-400" />
                Scan Configuration
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <Label className="text-slate-300">Select Scan Mode</Label>
                <Tabs value={scanMode} onValueChange={setScanMode} className="mt-2">
                  <TabsList className="grid w-full grid-cols-2">
                    <TabsTrigger value="basic">Basic Scan</TabsTrigger>
                    <TabsTrigger value="advanced">Advanced Scan</TabsTrigger>
                  </TabsList>
                  
                  <TabsContent value="basic" className="mt-4 space-y-2">
                    <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-4">
                      <h3 className="text-blue-300 font-semibold mb-2">Basic Scan Features:</h3>
                      <ul className="text-slate-300 space-y-1 text-sm">
                        <li>• AI-powered vulnerability detection with Gemini</li>
                        <li>• Real-time scanning progress</li>
                        <li>• Standard security checks</li>
                        <li>• Fast results</li>
                      </ul>
                    </div>
                  </TabsContent>
                  
                  <TabsContent value="advanced" className="mt-4 space-y-2">
                    <div className="bg-purple-500/10 border border-purple-500/30 rounded-lg p-4">
                      <h3 className="text-purple-300 font-semibold mb-2">Advanced Scan Features:</h3>
                      <ul className="text-slate-300 space-y-1 text-sm">
                        <li>• <strong>AST Parsing:</strong> Deep code structure analysis</li>
                        <li>• <strong>Taint Analysis:</strong> Track data flow across components</li>
                        <li>• <strong>Pattern Recognition:</strong> Known vulnerability signatures</li>
                        <li>• <strong>Cross-Language Detection:</strong> Security gaps at language boundaries</li>
                        <li>• <strong>Unified IR:</strong> Multi-language code representation</li>
                      </ul>
                    </div>
                  </TabsContent>
                </Tabs>
              </div>

              <div>
                <Label htmlFor="github-url" className="text-slate-300">
                  GitHub Repository URL
                </Label>
                <div className="flex gap-2 mt-2">
                  <div className="relative flex-1">
                    <Github className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-400" />
                    <Input
                      id="github-url"
                      type="url"
                      placeholder="https://github.com/username/repository"
                      value={githubUrl}
                      onChange={(e) => setGithubUrl(e.target.value)}
                      disabled={scanning}
                      className="pl-10 bg-slate-900/50 border-slate-600 text-white placeholder-slate-400"
                    />
                  </div>
                  <Button
                    onClick={handleStartScan}
                    disabled={scanning}
                    className={`${
                      scanMode === 'advanced'
                        ? 'bg-purple-600 hover:bg-purple-700'
                        : 'bg-blue-600 hover:bg-blue-700'
                    } text-white px-6`}
                  >
                    {scanning ? (
                      <>
                        <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                        Scanning...
                      </>
                    ) : (
                      <>
                        <Shield className="w-4 h-4 mr-2" />
                        Start {scanMode === 'advanced' ? 'Advanced' : 'Basic'} Scan
                      </>
                    )}
                  </Button>
                </div>
                <p className="text-slate-400 text-sm mt-2">
                  Example: https://github.com/octocat/Hello-World
                </p>
              </div>
            </CardContent>
          </Card>

          {/* Scanning Progress */}
          {scanning && (
            <Card className="bg-slate-800/50 border-slate-700 backdrop-blur-sm mb-6">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <Loader2 className="w-5 h-5 animate-spin text-purple-400" />
                  {scanMode === 'advanced' ? 'Advanced Analysis' : 'Scanning'} in Progress
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-6">
                {/* Progress Bar */}
                <div>
                  <div className="flex justify-between text-sm mb-2">
                    <span className="text-slate-300">Overall Progress</span>
                    <span className="text-purple-400 font-semibold">{scanProgress}%</span>
                  </div>
                  <Progress value={scanProgress} className="h-2" />
                </div>

                {/* Current Stage - Advanced Mode Only */}
                {scanMode === 'advanced' && stageInfo && (
                  <div className="bg-purple-500/10 border border-purple-500/30 rounded-lg p-4">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 bg-purple-500/20 rounded-full flex items-center justify-center">
                        <stageInfo.icon className="w-5 h-5 text-purple-400" />
                      </div>
                      <div className="flex-1">
                        <h3 className="text-white font-semibold">{stageInfo.name}</h3>
                        <p className="text-slate-400 text-sm">{stageInfo.description}</p>
                      </div>
                      <Loader2 className="w-5 h-5 animate-spin text-purple-400" />
                    </div>
                  </div>
                )}

                {/* Status Message */}
                {statusMessage && (
                  <div className="text-slate-300 text-center py-2">
                    {statusMessage}
                  </div>
                )}

                {/* Statistics */}
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <div className="bg-slate-900/50 rounded-lg p-4 text-center">
                    <div className="text-2xl font-bold text-white">{totalFiles}</div>
                    <div className="text-slate-400 text-sm">Total Files</div>
                  </div>
                  <div className="bg-slate-900/50 rounded-lg p-4 text-center">
                    <div className="text-2xl font-bold text-blue-400">{filesAnalyzed}</div>
                    <div className="text-slate-400 text-sm">Analyzed</div>
                  </div>
                  <div className="bg-slate-900/50 rounded-lg p-4 text-center">
                    <div className="text-2xl font-bold text-red-400">{vulnerabilitiesFound}</div>
                    <div className="text-slate-400 text-sm">Vulnerabilities</div>
                  </div>
                  {scanMode === 'advanced' && (
                    <div className="bg-slate-900/50 rounded-lg p-4 text-center">
                      <div className="text-2xl font-bold text-purple-400">{crossLangVulns}</div>
                      <div className="text-slate-400 text-sm">Cross-Language</div>
                    </div>
                  )}
                </div>

                {/* Analysis Stages - Advanced Mode Only */}
                {scanMode === 'advanced' && (
                  <div>
                    <h3 className="text-white font-semibold mb-3">Analysis Pipeline</h3>
                    <div className="space-y-2">
                      {ANALYSIS_STAGES.map((stage, idx) => {
                        const isCompleted = completedStages.some(s => s.id === stage.id);
                        const isCurrent = currentStage === stage.id;
                        
                        return (
                          <div
                            key={stage.id}
                            className={`flex items-center gap-3 p-3 rounded-lg transition-colors ${
                              isCurrent
                                ? 'bg-purple-500/20 border border-purple-500/40'
                                : isCompleted
                                ? 'bg-green-500/10 border border-green-500/30'
                                : 'bg-slate-800/30 border border-slate-700'
                            }`}
                          >
                            <div className={`w-8 h-8 rounded-full flex items-center justify-center ${
                              isCurrent
                                ? 'bg-purple-500/30'
                                : isCompleted
                                ? 'bg-green-500/30'
                                : 'bg-slate-700'
                            }`}>
                              {isCompleted ? (
                                <CheckCircle2 className="w-4 h-4 text-green-400" />
                              ) : isCurrent ? (
                                <Loader2 className="w-4 h-4 text-purple-400 animate-spin" />
                              ) : (
                                <stage.icon className="w-4 h-4 text-slate-500" />
                              )}
                            </div>
                            <div className="flex-1">
                              <div className={`font-medium ${
                                isCurrent || isCompleted ? 'text-white' : 'text-slate-500'
                              }`}>
                                {stage.name}
                              </div>
                              <div className="text-xs text-slate-400">{stage.description}</div>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}

                {/* Current File */}
                {currentFile && (
                  <div className="bg-slate-900/50 rounded-lg p-4">
                    <div className="flex items-center gap-2 text-slate-300">
                      <FileCode className="w-4 h-4" />
                      <span className="text-sm">Analyzing: {currentFile}</span>
                    </div>
                  </div>
                )}

                {/* Recently Scanned Files */}
                {scannedFiles.length > 0 && (
                  <div>
                    <h3 className="text-white font-semibold mb-2">Recently Scanned</h3>
                    <div className="space-y-1 max-h-40 overflow-y-auto">
                      {scannedFiles.slice(-10).reverse().map((file, idx) => (
                        <div
                          key={idx}
                          className="flex items-center gap-2 p-2 bg-slate-900/30 rounded text-sm"
                        >
                          <CheckCircle2 className="w-4 h-4 text-green-400 flex-shrink-0" />
                          <span className="text-slate-300 truncate">{file.path}</span>
                          <Badge variant="outline" className="ml-auto text-xs">
                            {file.language}
                          </Badge>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          )}

          {/* Info Cards */}
          {!scanning && (
            <div className="grid md:grid-cols-3 gap-6">
              <Card className="bg-slate-800/50 border-slate-700 backdrop-blur-sm">
                <CardContent className="pt-6">
                  <div className="w-12 h-12 bg-purple-500/20 rounded-full flex items-center justify-center mb-4">
                    <Code className="w-6 h-6 text-purple-400" />
                  </div>
                  <h3 className="text-white font-semibold mb-2">Multi-Language Support</h3>
                  <p className="text-slate-400 text-sm">
                    Analyze code in Python, JavaScript, TypeScript, Java, Go, and Rust
                  </p>
                </CardContent>
              </Card>

              <Card className="bg-slate-800/50 border-slate-700 backdrop-blur-sm">
                <CardContent className="pt-6">
                  <div className="w-12 h-12 bg-purple-500/20 rounded-full flex items-center justify-center mb-4">
                    <Network className="w-6 h-6 text-purple-400" />
                  </div>
                  <h3 className="text-white font-semibold mb-2">Cross-Language Detection</h3>
                  <p className="text-slate-400 text-sm">
                    Identify security gaps at integration points between different languages
                  </p>
                </CardContent>
              </Card>

              <Card className="bg-slate-800/50 border-slate-700 backdrop-blur-sm">
                <CardContent className="pt-6">
                  <div className="w-12 h-12 bg-purple-500/20 rounded-full flex items-center justify-center mb-4">
                    <Eye className="w-6 h-6 text-purple-400" />
                  </div>
                  <h3 className="text-white font-semibold mb-2">Deep Taint Analysis</h3>
                  <p className="text-slate-400 text-sm">
                    Track vulnerable data flows across your entire application stack
                  </p>
                </CardContent>
              </Card>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
